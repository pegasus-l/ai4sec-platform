"""L5: 一 run 一个受限模型令牌。

这一层守的不是"令牌能不能发", 而是四件**发错了就查不出来**的事:

  · 令牌以明文躺在库里(库被读走 = 凭证被读走);
  · 过期/吊销/超预算时"放行"—— 账外成本不会自己冒出来;
  · 令牌能证明"我是某一轮"之外的东西(能调判分接口、能跨轮用);
  · 工具把令牌抄进 recipe —— 下一轮跑的还是上一轮的凭证, 而且它会跟着配置被看到。
"""
from __future__ import annotations

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from ai4sec_platform.app.main import app
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities.eval import llm_tokens
from ai4sec_platform.domains.capabilities.eval import samples as S
from ai4sec_platform.domains.capabilities.eval import store

DIFF = """diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,4 +1,4 @@
 alpha
-VULN(x)
+SAFE(x)
 beta
"""


@pytest.fixture()
def conn() -> sqlite3.Connection:
    c = connect()
    init_db(c)
    yield c
    c.close()


def _run(conn: sqlite3.Connection) -> int:
    """开一轮 running 的评测: 令牌挂在 run 上, 没有 run 就没有令牌。"""
    return store.create_run(conn, item_id=1, repeats=1)


# ── 令牌本身 ──────────────────────────────────────────────────────────────────

def test_the_token_is_not_stored_in_the_clear(conn):
    minted = llm_tokens.mint(conn, _run(conn))
    row = conn.execute("SELECT * FROM capability_eval_llm_tokens").fetchone()
    assert minted["token"].startswith(llm_tokens.TOKEN_PREFIX)
    # 库里任何一列都不许出现明文 —— 只看 token_hash 不够, 以后加列也要被这条挡住
    assert minted["token"] not in "".join(str(v) for v in dict(row).values())
    assert row["token_hash"] == llm_tokens._hash(minted["token"])


def test_a_fresh_token_verifies_and_a_forged_one_does_not(conn):
    minted = llm_tokens.mint(conn, _run(conn))
    assert llm_tokens.verify(conn, minted["token"])["run_id"] == 1
    with pytest.raises(llm_tokens.LlmTokenError) as exc:
        llm_tokens.verify(conn, llm_tokens.TOKEN_PREFIX + "not-a-real-token")
    assert exc.value.status == 401
    # 前缀不对的直接拒, 连查库都不查 —— 平台的 EVAL_TOKEN 之类不能被当成轮次令牌试
    with pytest.raises(llm_tokens.LlmTokenError):
        llm_tokens.verify(conn, "some-other-token")


def test_reclaiming_kills_the_previous_token(conn):
    run_id = _run(conn)
    first = llm_tokens.mint(conn, run_id)
    second = llm_tokens.mint(conn, run_id)
    with pytest.raises(llm_tokens.LlmTokenError) as exc:
        llm_tokens.verify(conn, first["token"])
    assert exc.value.detail == "revoked"
    assert llm_tokens.verify(conn, second["token"])["run_id"] == run_id


def test_an_expired_token_does_not_verify(conn):
    minted = llm_tokens.mint(conn, _run(conn))
    # 直接把到期时间拨到过去: 比 sleep 一秒更确定, 也不会让用例变慢
    conn.execute("UPDATE capability_eval_llm_tokens SET expires_at='2000-01-01T00:00:00+00:00'")
    conn.commit()
    with pytest.raises(llm_tokens.LlmTokenError) as exc:
        llm_tokens.verify(conn, minted["token"])
    assert exc.value.detail == "expired"


def test_the_budget_is_counted_in_real_numbers(conn):
    run_id = _run(conn)
    minted = llm_tokens.mint(conn, run_id, max_calls=2, max_tokens=1000)
    row = llm_tokens.verify(conn, minted["token"])
    llm_tokens.charge(conn, row["token_hash"], {"prompt_tokens": 10, "completion_tokens": 5})
    llm_tokens.charge(conn, row["token_hash"], {"prompt_tokens": 1, "completion_tokens": 1})
    with pytest.raises(llm_tokens.LlmTokenError) as exc:
        llm_tokens.verify(conn, minted["token"])
    assert exc.value.status == 429


def test_a_token_budget_also_stops_the_run(conn):
    run_id = _run(conn)
    minted = llm_tokens.mint(conn, run_id, max_calls=0, max_tokens=10)
    row = llm_tokens.verify(conn, minted["token"])
    llm_tokens.charge(conn, row["token_hash"], {"prompt_tokens": 8, "completion_tokens": 4})
    with pytest.raises(llm_tokens.LlmTokenError) as exc:
        llm_tokens.verify(conn, minted["token"])
    assert "token" in exc.value.detail


def test_usage_without_numbers_still_counts_the_call(conn):
    """上游没给 usage 时只记次数 —— 不拿请求里的 max_tokens 去估一个假的用量。"""
    run_id = _run(conn)
    minted = llm_tokens.mint(conn, run_id)
    row = llm_tokens.verify(conn, minted["token"])
    llm_tokens.charge(conn, row["token_hash"], None)
    summary = llm_tokens.summary(conn, run_id)
    assert summary["calls"] == 1 and summary["total_tokens"] == 0


def test_summary_says_what_was_used_not_what_was_allowed(conn):
    run_id = _run(conn)
    minted = llm_tokens.mint(conn, run_id, max_calls=10, max_tokens=100)
    row = llm_tokens.verify(conn, minted["token"])
    llm_tokens.charge(conn, row["token_hash"], {"prompt_tokens": 30, "completion_tokens": 20})
    summary = llm_tokens.summary(conn, run_id)
    assert summary == {"calls": 1, "prompt_tokens": 30, "completion_tokens": 20,
                       "total_tokens": 50, "max_calls": 10, "max_tokens": 100,
                       "budget_exceeded": False}
    # 金额不存在: 网关对未登记价目表的模型一律记 $0.0, 编一个价格出来比不报更糟
    assert "spend_usd" not in summary


def test_no_token_means_no_summary(conn):
    assert llm_tokens.summary(conn, _run(conn)) == {"calls": 0}


# ── OpenAI 兼容入口 ───────────────────────────────────────────────────────────

def _post_completion(client: TestClient, token: str, body: dict | None = None):
    payload = body or {"model": "chat-primary",
                       "messages": [{"role": "user", "content": "hi"}]}
    return client.post("/api/internal/eval/v1/chat/completions", json=payload,
                       headers={"Authorization": f"Bearer {token}"})


def test_an_unknown_token_gets_an_openai_shaped_401(conn):
    resp = _post_completion(TestClient(app), "caev1_nope")
    assert resp.status_code == 401
    # 各家 SDK 只认这个形状, 回 {"detail": ...} 会让工具报一个跟原因无关的解析错
    assert resp.json()["error"]["code"] == "token"


def test_streaming_is_refused_by_name(conn):
    run_id = _run(conn)
    token = llm_tokens.mint(conn, run_id)["token"]
    assert _post_completion(TestClient(app), token,
                            {"stream": True, "messages": [{"role": "user", "content": "x"}]}
                            ).json()["error"]["code"] == "stream_not_supported"


def test_the_legacy_functions_api_says_what_to_use_instead(conn):
    """不替调用方把 functions 翻译成 tools: 翻错了对方拿到的是它没要的形状,
    报出来的错跟真正原因无关。名字里写清该改用哪个。"""
    token = llm_tokens.mint(conn, _run(conn))["token"]
    body = _post_completion(TestClient(app), token,
                            {"messages": [{"role": "user", "content": "x"}],
                             "functions": [{"name": "report_finding"}]}).json()
    assert body["error"]["code"] == "legacy_function_call"
    assert "tools" in body["error"]["message"]


def _router_returns(monkeypatch, result: dict) -> list[dict]:
    """把 LLMRouter 换成"配了模型 + 返回固定结果", 并把它收到的 kwargs 记下来。"""
    from ai4sec_platform.models.router import LLMRouter
    calls: list[dict] = []
    monkeypatch.setattr(LLMRouter, "active_config",
                        lambda self, profile="configured_model": {
                            "provider": "ai4sec_openai", "configured": True,
                            "model": "chat-primary", "max_output_tokens": 4096})

    def _fake(self, **kwargs):
        calls.append(kwargs)
        return dict(result)

    monkeypatch.setattr(LLMRouter, "chat_completion", _fake)
    return calls


TOOLS = [{"type": "function",
          "function": {"name": "report_finding",
                       "parameters": {"type": "object",
                                      "properties": {"line": {"type": "integer"}}}}}]


def test_function_calling_is_forwarded_and_tool_calls_come_back(conn, monkeypatch):
    """被测工具用 `with_structured_output` 拿结论 —— 这条路必须真的通。

    2026-11-03: 之前这一层把 `tools` 直接拒了, 适配 agent 只能判"工具需要 function
    calling, 放弃"。上游网关本来就支持, 卡点在平台的五行拒绝上。
    """
    token = llm_tokens.mint(conn, _run(conn))["token"]
    calls = _router_returns(monkeypatch, {
        "content": None, "finish_reason": "tool_calls",
        "tool_calls": [{"id": "call_1", "type": "function",
                        "function": {"name": "report_finding", "arguments": "{\"line\": 42}"}}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 1}, "serving": {}})

    body = _post_completion(TestClient(app), token,
                            {"messages": [{"role": "user", "content": "audit app.py"}],
                             "tools": TOOLS, "tool_choice": "auto",
                             "response_format": {"type": "json_object"}}).json()

    # 1) 三个参数原样到了模型那层 —— 少传一个, 工具就会退化成"让模型输出 JSON 再正则"
    assert calls and calls[0]["tools"] == TOOLS
    assert calls[0]["tool_choice"] == "auto"
    assert calls[0]["response_format"] == {"type": "json_object"}
    # 2) tool_calls 原样带回, content 按约定是 null(不是空串)
    message = body["choices"][0]["message"]
    assert message["tool_calls"][0]["id"] == "call_1"
    assert message["tool_calls"][0]["function"]["arguments"] == "{\"line\": 42}"
    assert message["content"] is None
    assert body["choices"][0]["finish_reason"] == "tool_calls"


def test_the_tool_turn_goes_back_up_with_its_call_id(conn, monkeypatch):
    """工具把工具函数的返回值喂回去时, `tool` 角色 + `tool_call_id` 必须能过;
    上一轮 assistant 的 tool_calls 也要原样带着, 否则上游会认不出这是同一次对话。"""
    token = llm_tokens.mint(conn, _run(conn))["token"]
    calls = _router_returns(monkeypatch, {"content": "done", "finish_reason": "stop",
                                          "usage": {}, "serving": {}})
    prior = {"id": "call_1", "type": "function",
             "function": {"name": "report_finding", "arguments": "{}"}}
    _post_completion(TestClient(app), token,
                     {"messages": [{"role": "user", "content": "audit"},
                                   {"role": "assistant", "content": None, "tool_calls": [prior]},
                                   {"role": "tool", "tool_call_id": "call_1", "content": "ok"}],
                      "tools": TOOLS})

    sent = calls[0]["messages"]
    assert sent[1]["tool_calls"] == [prior]
    # 带 tool_calls 的 assistant 回合原样是 null, 不能变成空串
    assert sent[1]["content"] is None
    assert sent[2] == {"role": "tool", "content": "ok", "tool_call_id": "call_1"}


def test_a_tool_message_without_a_call_id_is_refused_by_name(conn):
    token = llm_tokens.mint(conn, _run(conn))["token"]
    body = _post_completion(TestClient(app), token,
                            {"messages": [{"role": "tool", "content": "x"}]}).json()
    # 上游拒这条时给的是含糊的 "invalid request", 在这里说清是漏了 id
    assert body["error"]["code"] == "bad_messages"
    assert "tool_call_id" in body["error"]["message"]


def test_without_a_configured_model_the_answer_is_503_not_a_rule_engine(conn, monkeypatch):
    run_id = _run(conn)
    token = llm_tokens.mint(conn, run_id)["token"]
    from ai4sec_platform.models.router import LLMRouter
    monkeypatch.setattr(LLMRouter, "active_config",
                        lambda self, profile="configured_model": {"provider": "local_rules",
                                                                  "configured": False})
    resp = _post_completion(TestClient(app), token)
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "model_unconfigured"
    # 一次没跑成的调用不能被记成一次用量
    assert llm_tokens.summary(conn, run_id)["calls"] == 0


def test_a_successful_call_comes_back_in_openai_shape_and_is_charged(conn, monkeypatch):
    run_id = _run(conn)
    token = llm_tokens.mint(conn, run_id)["token"]
    from ai4sec_platform.models.router import LLMRouter

    monkeypatch.setattr(LLMRouter, "active_config",
                        lambda self, profile="configured_model": {
                            "provider": "ai4sec_openai", "configured": True,
                            "model": "chat-primary", "max_output_tokens": 4096})
    monkeypatch.setattr(LLMRouter, "chat_completion",
                        lambda self, **kw: {"content": "hello", "finish_reason": "stop",
                                            "usage": {"prompt_tokens": 7, "completion_tokens": 3},
                                            "serving": {"upstream_model": "openai/deepseek-v4-flash"}})

    body = _post_completion(TestClient(app), token).json()
    assert body["object"] == "chat.completion"
    assert body["choices"][0]["message"] == {"role": "assistant", "content": "hello"}
    assert body["usage"] == {"prompt_tokens": 7, "completion_tokens": 3}
    # 回给工具的是它请求的模型名, 真正是谁答的在 serving 里 —— 两者不能混
    assert body["model"] == "chat-primary"
    assert body["serving"]["upstream_model"] == "openai/deepseek-v4-flash"
    assert llm_tokens.summary(conn, run_id)["total_tokens"] == 10


def test_models_endpoint_answers_so_tools_do_not_die_on_404(conn, monkeypatch):
    token = llm_tokens.mint(conn, _run(conn))["token"]
    from ai4sec_platform.models.router import LLMRouter
    monkeypatch.setattr(LLMRouter, "active_config",
                        lambda self, profile="configured_model": {"model": "chat-primary",
                                                                  "configured": True,
                                                                  "provider": "ai4sec_openai"})
    body = TestClient(app).get("/api/internal/eval/v1/models",
                               headers={"Authorization": f"Bearer {token}"}).json()
    assert body["data"][0]["id"] == "chat-primary"


# ── claim / finish 接线 ───────────────────────────────────────────────────────

def _ingest(conn, tmp_path):
    src = S.CaseSource(case_id=1, canonical_id="CVE-2026-1002", repo="acme/app",
                       commit_sha="a" * 40, file_path="app.py", function="handler",
                       line_start=2, line_end=2, cwe="CWE-78", published_at="2026-10-20",
                       vuln_content="VULN(x)", patch_diff=DIFF)
    S.build_dataset([src], lambda repo, ref, path: "alpha\nSAFE(x)\nbeta\n",
                    tmp_path / "ds", limit=1)


def test_claim_hands_out_a_token_and_finish_revokes_it(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("EVAL_TOKEN", "eval-secret")
    _ingest(conn, tmp_path)
    store.ingest_dataset(conn, tmp_path / "ds")
    run_id = store.create_run(conn, item_id=1, repeats=1)
    client = TestClient(app)

    claimed = client.post("/api/internal/eval/claim", json={},
                          headers={"X-Repro-Token": "eval-secret"}).json()
    token = claimed["llm"]["token"]
    assert claimed["llm"]["model"] and claimed["llm"]["max_calls"] > 0
    assert llm_tokens.verify(conn, token)["run_id"] == run_id

    client.post(f"/api/internal/eval/runs/{run_id}/finish",
                json={"status": "failed", "failure_reason": "timeout", "score": False},
                headers={"X-Repro-Token": "eval-secret"})
    with pytest.raises(llm_tokens.LlmTokenError):
        llm_tokens.verify(conn, token)


def test_a_run_that_burned_the_model_budget_is_not_recorded_as_success(conn, tmp_path, monkeypatch):
    """令牌侧超预算 = 这一轮跑出来的数不代表工具的能力。记成 success 会误导页面。"""
    monkeypatch.setenv("EVAL_TOKEN", "eval-secret")
    _ingest(conn, tmp_path)
    store.ingest_dataset(conn, tmp_path / "ds")
    run_id = store.create_run(conn, item_id=1, repeats=1, budget={"llm_max_calls": 1})
    client = TestClient(app)
    token = client.post("/api/internal/eval/claim", json={},
                        headers={"X-Repro-Token": "eval-secret"}).json()["llm"]["token"]
    row = llm_tokens.verify(conn, token)
    llm_tokens.charge(conn, row["token_hash"], {"prompt_tokens": 1, "completion_tokens": 1})

    client.post(f"/api/internal/eval/runs/{run_id}/finish",
                json={"status": "success", "score": False},
                headers={"X-Repro-Token": "eval-secret"})

    run = store.get_run(conn, run_id)
    assert run["status"] == "budget_exceeded"
    assert run["cost_json"]["llm_key"]["calls"] == 1


def test_allow_llm_false_means_no_token_at_all(conn, tmp_path, monkeypatch):
    monkeypatch.setenv("EVAL_TOKEN", "eval-secret")
    _ingest(conn, tmp_path)
    store.ingest_dataset(conn, tmp_path / "ds")
    store.create_run(conn, item_id=1, repeats=1, budget={"allow_llm": False})
    claimed = TestClient(app).post("/api/internal/eval/claim", json={},
                                   headers={"X-Repro-Token": "eval-secret"}).json()
    assert claimed["llm"] is None
