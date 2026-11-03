"""容器间内部接口(评测执行位领活/交卷/收尾)。

这一层最容易出的不是业务错, 是**把不该给的东西给了**:
  · 领活时把真值一并发出去 —— 被测工具看到答案, 评测就不成立了
  · 没有答卷就收尾成 success —— 页面上出现一份"零样本的成功评测"
  · 令牌没配也放行 —— 任何能连到 8100 的容器都能改评测结果
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai4sec_platform.app.main import app
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities.eval import samples as S
from ai4sec_platform.domains.capabilities.eval import store

TOKEN = "unit-test-token"
DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 alpha
 beta
-VULN(x)
+SAFE(x)
+also_safe(x)
 gamma
 delta
"""
POST = "alpha\nbeta\nSAFE(x)\nalso_safe(x)\ngamma\ndelta"
PRE_ANSWER = json.dumps({"found": True, "findings": [{
    "file": "app.py", "function": "handler", "line_start": 3, "line_end": 3,
    "type_cwe": "CWE-78", "evidence": "stub"}]})
CLEAN_ANSWER = json.dumps({"found": False, "findings": []})


@pytest.fixture()
def conn() -> sqlite3.Connection:
    c = connect()
    init_db(c)
    yield c
    c.close()


@pytest.fixture()
def client(monkeypatch) -> TestClient:
    monkeypatch.setenv("REPRO_PASSWORD", TOKEN)
    return TestClient(app)


def _post(client: TestClient, path: str, body: dict | None = None, token: str = TOKEN):
    return client.post(path, json=body or {}, headers={"X-Repro-Token": token})


def _dataset(tmp_path: Path) -> Path:
    src = S.CaseSource(
        case_id=1, canonical_id="CVE-2026-1001", repo="acme/app", commit_sha="a" * 40,
        file_path="app.py", function="handler", line_start=3, line_end=3, cwe="CWE-78",
        published_at="2026-10-20", vuln_content="VULN(x)", patch_diff=DIFF,
    )
    S.build_dataset([src], lambda repo, ref, path: POST, tmp_path / "ds", limit=1)
    return tmp_path / "ds"


def _running(conn, tmp_path, repeats: int = 3) -> int:
    store.ingest_dataset(conn, _dataset(tmp_path))
    return store.create_run(conn, item_id=1, repeats=repeats)


def _keys(conn):
    rows = store.list_samples(conn)
    pre = next(r["sample_key"] for r in rows if r["polarity"] == "pre")
    post = next(r["sample_key"] for r in rows if r["polarity"] == "post")
    return pre, post


def test_claim_refuses_without_the_shared_token(client, conn, tmp_path):
    _running(conn, tmp_path)
    assert _post(client, "/api/internal/eval/claim", token="wrong").status_code == 401
    assert _post(client, "/api/internal/eval/claim", token="").status_code == 401


def test_claim_is_off_when_no_token_is_configured(client, conn, tmp_path, monkeypatch):
    """没配令牌不是"谁都能进", 而是**根本不能用** —— 否则等于把写入口敞开。"""
    monkeypatch.delenv("REPRO_PASSWORD", raising=False)
    _running(conn, tmp_path)
    assert _post(client, "/api/internal/eval/claim").status_code == 503


def test_claim_says_idle_instead_of_erroring(client):
    body = _post(client, "/api/internal/eval/claim").json()
    assert body == {"run": None}


def test_claim_never_ships_the_ground_truth(client, conn, tmp_path):
    _running(conn, tmp_path)
    body = _post(client, "/api/internal/eval/claim").json()
    assert body["run"]["run_id"] and body["samples"]
    for sample in body["samples"]:
        # 白名单投影: 只发题面, 不发任何能直接判对错的列
        assert set(sample) == {"sample_key", "prompt", "file_name", "file_content",
                               "relative_path", "artifact_hash"}
        assert "CVE-2026-1001" not in json.dumps(sample)
    # 整包再查一遍: 真值里的判据一个都不许出现在响应里
    blob = json.dumps(body)
    for leak in ("ground_truth", "polarity", "valid_until", "published_at", "case_id"):
        assert leak not in blob


def test_claim_tells_the_runner_where_the_tool_lives(client, conn, tmp_path):
    """没 recipe 时执行位要自己 clone 源码来适配(D4) —— 地址必须由平台给, 不能让它猜。"""
    store.ingest_dataset(conn, _dataset(tmp_path))
    item_id = repo.create_domain_item(
        conn, domain="capabilities", item_type="capability", title="audit-tool",
        source_url="https://arxiv.org/abs/2601.00001",
        payload={"code_url": "acme/audit-tool", "git_ref": "v1.2.3"})
    conn.commit()
    store.create_run(conn, item_id=item_id, repeats=3)

    body = _post(client, "/api/internal/eval/claim").json()
    assert body["tool"] == {"item_id": item_id, "name": "audit-tool",
                            "repo_url": "https://github.com/acme/audit-tool",
                            "git_ref": "v1.2.3"}


def test_claim_says_nothing_about_a_tool_it_cannot_find(client, conn, tmp_path):
    """条目没了就不给地址 —— 执行位会落 repo_unavailable, 比拿个猜的 URL 去 clone 强。"""
    _running(conn, tmp_path)          # run 指向的 item 在库里并不存在
    body = _post(client, "/api/internal/eval/claim").json()
    assert body["tool"] == {} and body["run"]["run_id"]


def test_claim_takes_the_oldest_run(client, conn, tmp_path):
    first = _running(conn, tmp_path)
    conn.execute("UPDATE capability_eval_runs SET started_at='2026-11-02T00:00:00Z' WHERE id=?", (first,))
    second = store.create_run(conn, item_id=2, repeats=3)
    conn.execute("UPDATE capability_eval_runs SET started_at='2026-11-02T01:00:00Z' WHERE id=?", (second,))
    conn.commit()
    assert _post(client, "/api/internal/eval/claim").json()["run"]["run_id"] == first


def test_claim_flags_a_half_done_run(client, conn, tmp_path):
    run_id = _running(conn, tmp_path)
    pre, _ = _keys(conn)
    _post(client, f"/api/internal/eval/runs/{run_id}/answers",
          {"answers": {pre: [PRE_ANSWER] * 3}})
    assert _post(client, "/api/internal/eval/claim").json()["run"]["has_answers"] is True


def test_answers_then_finish_scores_and_lands_a_report(client, conn, tmp_path):
    run_id = _running(conn, tmp_path)
    pre, post = _keys(conn)
    resp = _post(client, f"/api/internal/eval/runs/{run_id}/answers",
                 {"answers": {pre: [PRE_ANSWER] * 3, post: [CLEAN_ANSWER] * 3}})
    assert resp.status_code == 200 and resp.json()["saved"] == 6

    body = _post(client, f"/api/internal/eval/runs/{run_id}/finish", {"status": "success"}).json()
    assert body == {"status": "success", "scored": True, "n_samples": 2, "n_excluded": 0}
    run = store.get_run(conn, run_id)
    assert run["status"] == "success" and run["report"]["n_samples"] == 2
    assert conn.execute(
        "SELECT COUNT(*) FROM capability_eval_reports WHERE run_id=?", (run_id,)).fetchone()[0] == 1


def test_an_out_of_scope_sample_leaves_the_denominator_end_to_end(client, conn, tmp_path):
    """工具说"这类样本我不覆盖" 的样本, 从交卷到报表都不能算进分母(D4-5)。

    这条走的是完整的内部接口链路: 交卷 → 收尾 → 报表, 而不是只测 store 或只测判分。
    少任何一环, 都会出现"页面上一份分数把不支持的语言算成没找到"。
    """
    run_id = _running(conn, tmp_path)
    pre, post = _keys(conn)
    out_of_scope = {"raw": "unsupported language: rust", "answer": None,
                    "excluded": "language_not_supported"}
    resp = _post(client, f"/api/internal/eval/runs/{run_id}/answers",
                 {"answers": {pre: [PRE_ANSWER] * 3, post: [out_of_scope] * 3}})
    assert resp.status_code == 200 and resp.json()["saved"] == 6

    body = _post(client, f"/api/internal/eval/runs/{run_id}/finish", {"status": "success"}).json()
    assert body == {"status": "success", "scored": True, "n_samples": 2, "n_excluded": 1}
    report = store.get_run(conn, run_id)["report"]
    assert report["n_samples"] == 2 and report["n_excluded"] == 1
    assert report["excluded_reasons"] == {"language_not_supported": 1}
    first = report["per_repeat"]["r1"]
    # 分母只剩 pre 一条; 被排除的那条既不进 positives 也不进 invalid
    assert first["n"]["total"] == 1 and first["n"]["excluded"] == 1
    assert first["labels"]["invalid_output"] == 0
    assert report["answers_missing"] == []          # 被排除 ≠ 漏交


def test_finish_success_without_answers_is_refused(client, conn, tmp_path):
    run_id = _running(conn, tmp_path)
    assert _post(client, f"/api/internal/eval/runs/{run_id}/finish",
                 {"status": "success"}).status_code == 409
    # 拒绝不能留痕: run 必须还是 running, 等下一轮
    assert store.get_run(conn, run_id)["status"] == "running"


def test_finish_failed_is_terminal_and_carries_the_reason(client, conn, tmp_path):
    run_id = _running(conn, tmp_path)
    body = _post(client, f"/api/internal/eval/runs/{run_id}/finish",
                 {"status": "failed", "failure_reason": "needs_paid_key"}).json()
    assert body["scored"] is False
    run = store.get_run(conn, run_id)
    assert run["status"] == "failed" and run["failure_reason"] == "needs_paid_key"
    # 失败不是成绩: 不许留报告
    assert conn.execute(
        "SELECT COUNT(*) FROM capability_eval_reports WHERE run_id=?", (run_id,)).fetchone()[0] == 0


def test_finish_unknown_status_is_rejected(client, conn, tmp_path):
    run_id = _running(conn, tmp_path)
    assert _post(client, f"/api/internal/eval/runs/{run_id}/finish",
                 {"status": "halfway"}).status_code == 400
    assert store.get_run(conn, run_id)["status"] == "running"


def test_answers_for_unknown_run_is_404(client):
    assert _post(client, "/api/internal/eval/runs/999/answers",
                 {"answers": {}}).status_code == 404


def test_answers_for_unknown_sample_are_reported_not_dropped(client, conn, tmp_path):
    run_id = _running(conn, tmp_path)
    pre, _ = _keys(conn)
    body = _post(client, f"/api/internal/eval/runs/{run_id}/answers",
                 {"answers": {pre: [PRE_ANSWER], "s_not_mine": [PRE_ANSWER]}}).json()
    assert body["unknown_samples"] == ["s_not_mine"]
    assert body["missing_samples"]  # 没交的样本要能被执行位看见


def test_sample_packets_projection_excludes_truth_at_the_store_layer(conn, tmp_path):
    _running(conn, tmp_path)
    for row in store.sample_packets(conn):
        assert set(row) == {"sample_key", "prompt", "file_name", "file_content",
                            "relative_path", "artifact_hash"}
        # 盘上的文件叫 code.py, 但工具报位置报的是原仓库路径 —— 这条路径必须给出去,
        # 否则判分时 path 对不上, 一次真命中会被记成 miss(2026-11-02 冒烟实测)
        assert row["relative_path"] == "app.py"


# ── D2/D3: 适配 agent 的两条内部接口 ──────────────────────────────────────────

GOOD_RECIPE = {"tool_version": "v1", "install": [],
               "invoke": ["./audit", "--file", "{sample_file}"], "output_parser": "json"}


def test_llm_is_refused_when_only_the_local_rule_engine_is_available(client):
    """没配模型时明确拒绝。返回一段规则引擎生成的摘要当"翻译结果", 就是编数据。"""
    body = {"profile": "capability_eval_adapter", "prompt": "x", "payload": {}}
    assert _post(client, "/api/internal/eval/llm", body).status_code == 503


def test_llm_profile_cannot_leave_the_eval_namespace(client):
    body = {"profile": "vulnerability_content_extractor", "prompt": "x", "payload": {}}
    response = _post(client, "/api/internal/eval/llm", body)
    assert response.status_code == 400 and "capability_eval_" in response.text


def test_llm_requires_the_token(client):
    assert _post(client, "/api/internal/eval/llm",
                 {"profile": "capability_eval_adapter", "prompt": "x"}, token="").status_code == 401


def test_llm_proxies_to_the_platform_model(client, monkeypatch):
    from ai4sec_platform.app.api import internal_eval

    class FakeRouter:
        def active_config(self, profile):
            return {"provider": "deepseek", "configured": True, "model": "m"}

        def complete_json(self, *, profile, prompt, payload):
            return {"parsed": {"action": "bash", "command": "ls"},
                    "model": "m", "provider": "deepseek"}

    monkeypatch.setattr(internal_eval, "LLMRouter", FakeRouter)
    body = {"profile": "capability_eval_adapter", "prompt": "x", "payload": {"step": 1}}
    response = _post(client, "/api/internal/eval/llm", body)
    assert response.status_code == 200
    assert response.json()["parsed"] == {"action": "bash", "command": "ls"}


def test_llm_passes_the_actually_serving_model_back(client, monkeypatch):
    """一份分数要能回答"它是哪家模型跑的"。平台把网关响应头原样交回去, 由执行位记进答卷/成本。

    读不到时回 `{}`, **不**拿配置里的别名顶上 —— 那会把"不知道"写成一条结论。
    """
    from ai4sec_platform.app.api import internal_eval

    class FakeRouter:
        def active_config(self, profile):
            return {"provider": "ai4sec_openai", "configured": True, "model": "chat-primary"}

        def complete_json(self, *, profile, prompt, payload):
            return {"parsed": {"ok": True}, "model": "chat-primary", "provider": "ai4sec_openai",
                    "serving": {"upstream_model": "openai/deepseek-v4-flash",
                                "upstream_group": "chat-primary",
                                "source": "gateway_header"},
                    "usage": {"total_tokens": 18}}

    monkeypatch.setattr(internal_eval, "LLMRouter", FakeRouter)
    body = {"profile": "capability_eval_adapter", "prompt": "x", "payload": {}}

    served = _post(client, "/api/internal/eval/llm", body).json()
    assert served["model"] == "chat-primary"
    assert served["serving"]["upstream_model"] == "openai/deepseek-v4-flash"
    assert served["usage"] == {"total_tokens": 18}

    class BareRouter(FakeRouter):
        def complete_json(self, *, profile, prompt, payload):
            return {"parsed": {"ok": True}, "model": "chat-primary", "provider": "ai4sec_openai"}

    monkeypatch.setattr(internal_eval, "LLMRouter", BareRouter)
    bare = _post(client, "/api/internal/eval/llm", body).json()
    assert bare["serving"] == {} and bare["usage"] == {}


def test_recipe_is_frozen_and_the_old_version_is_superseded_not_deleted(client, conn):
    first = _post(client, "/api/internal/eval/recipes",
                  {"item_id": 1, "tool_version": "v1", "recipe": GOOD_RECIPE}).json()
    assert first["created"] is True

    v2 = dict(GOOD_RECIPE, tool_version="v2")
    second = _post(client, "/api/internal/eval/recipes",
                   {"item_id": 1, "tool_version": "v2", "recipe": v2}).json()
    # 旧版不删: 一条分数要能回答"它当时按哪份配置跑的"
    assert second["superseded"] == [first["id"]]
    assert len(store.list_recipes(conn, 1)) == 2
    assert store.latest_recipe(conn, 1)["tool_version"] == "v2"


def test_resubmitting_the_same_version_updates_in_place(client, conn):
    _post(client, "/api/internal/eval/recipes",
          {"item_id": 2, "tool_version": "v1", "recipe": GOOD_RECIPE})
    changed = dict(GOOD_RECIPE, exploit_note="x", timeout_seconds=99)
    again = _post(client, "/api/internal/eval/recipes",
                  {"item_id": 2, "tool_version": "v1", "recipe": changed}).json()
    assert again["created"] is False and again["superseded"] == []
    assert len(store.list_recipes(conn, 2)) == 1
    assert store.latest_recipe(conn, 2)["recipe"]["timeout_seconds"] == 99


def test_a_recipe_without_invoke_never_lands_in_the_table(client, conn):
    broken = {"tool_version": "v9", "output_parser": "json"}
    response = _post(client, "/api/internal/eval/recipes",
                     {"item_id": 3, "tool_version": "v9", "recipe": broken})
    assert response.status_code == 400
    assert store.list_recipes(conn, 3) == []
