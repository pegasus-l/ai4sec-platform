"""评测执行位(`deploy/eval/runner.py`)的行为。

这个文件不在包里(它跑在另一个容器里, 只依赖标准库), 所以用 importlib 按路径加载。
守的是四类"看起来跑通了"的假象:
  · 参数被拼成一个 shell 字符串(样本路径是外部数据, 拼字符串就是命令注入)
  · 逐样本交卷时只发当前这一轮 → 平台按列表下标认轮次, 前面几轮被覆盖
  · 预算掐断时丢掉已经跑出来的答卷
  · 样本指纹不符却照跑(审的是另一份代码, 分数挂在原结论上)
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

RUNNER_PATH = Path(__file__).resolve().parents[2] / "deploy" / "eval" / "runner.py"


@pytest.fixture(scope="module")
def runner():
    spec = importlib.util.spec_from_file_location("cap_eval_runner", RUNNER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules["cap_eval_runner"] = module
    spec.loader.exec_module(module)
    return module


def _packet(key: str, content: str, name: str = "code.py") -> dict:
    return {"sample_key": key, "file_name": name, "file_content": content,
            "prompt": "audit this\n", "artifact_hash": hashlib.sha256(content.encode()).hexdigest()}


# ── 纯函数 ────────────────────────────────────────────────────────────────────

def test_render_substitutes_per_argument_and_never_joins(runner):
    argv = runner.render(["scan", "--file", "{sample_file}", "--tag", "{sample_key}"],
                         {"sample_file": "/tmp/a b.py", "sample_key": "s_1"})
    # 带空格的路径仍然是**一个**参数, 没有被拆成两个 —— 拼 shell 字符串就会拆开
    assert argv == ["scan", "--file", "/tmp/a b.py", "--tag", "s_1"]


def test_first_json_object_survives_prose_and_fences(runner):
    assert runner._first_json_object('{"found": false, "findings": []}')["found"] is False
    assert runner._first_json_object(
        'Here you go:\n```json\n{"found": true, "findings": []}\n```')["found"] is True
    assert runner._first_json_object(
        'I looked at it. {"found": false, "findings": []} Done.')["found"] is False
    assert runner._first_json_object("no json here") is None


def test_parse_answer_never_invents_a_verdict(runner):
    # 翻不出来就是翻不出来, 不许替工具答 "found=false"
    answer, why = runner.parse_answer({"kind": "json_stdout"}, "plain prose", returncode=0)
    assert answer is None and why == "no_json_in_stdout"
    answer, _ = runner.parse_answer({"kind": "exit_code"}, "", returncode=1)
    assert answer == {"found": True, "findings": []}   # 只回答"有没有", 不编位置


# ── 退出码语义: "有发现"不等于"跑失败"(D4, 2026-11-02 OpenAnt 实测) ──────────

FOUND_AND_EXIT_1 = [sys.executable, "-c",
                    "import json,sys;print(json.dumps({'found': True, 'findings': []}));"
                    "sys.exit(1)"]


def test_exit_1_counts_as_a_failure_unless_the_recipe_says_otherwise(runner, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    outcome = runner.Outcome()
    runner.execute(_run(), _recipe(FOUND_AND_EXIT_1), [_packet("s_0001", "x\n")],
                   tmp_path, {}, outcome)
    assert outcome.failures == 1


def test_a_findings_exit_code_is_a_successful_run(runner, tmp_path, monkeypatch):
    """扫描器用 1 表示"有发现"时, 那不是失败 —— 否则它每一轮都在"报错"。"""
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    outcome = runner.Outcome()
    runner.execute(_run(), _recipe(FOUND_AND_EXIT_1, ok_exit_codes=[0, 1]),
                   [_packet("s_0001", "x\n")], tmp_path, {}, outcome)
    assert outcome.failures == 0
    assert outcome.answers["s_0001"][0]["answer"]["found"] is True


def test_recipe_files_are_on_disk_before_the_tool_runs(runner, tmp_path, monkeypatch):
    """转换层必须来自 recipe 本体, 否则每次重跑都是另一份逻辑, 分数说不清。"""
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    shim = "import json;print(json.dumps({'found': False, 'findings': []}))"
    outcome = runner.Outcome()
    runner.execute(_run(), _recipe([sys.executable, "{workdir}/shim.py"], files={"shim.py": shim}),
                   [_packet("s_0001", "x\n")], tmp_path, {}, outcome)
    assert (tmp_path / "shim.py").read_text(encoding="utf-8") == shim
    assert outcome.answers["s_0001"][0]["answer"]["found"] is False


def test_recipe_files_cannot_be_written_outside_the_workdir(runner, tmp_path):
    for bad in ("../escape.py", "/etc/cron.d/x", ""):
        with pytest.raises(RuntimeError):
            runner._safe_join(tmp_path, bad)


# ── L5: 模型令牌 ──────────────────────────────────────────────────────────────

def _llm(token: str = "caev1_test-token") -> dict:
    return {"base_url": "http://ai4sec:8100/api/internal/eval/v1",
            "api_key": token, "model": "chat-primary"}


def test_llm_placeholders_reach_the_tool_but_install_log_does_not_leak(runner, tmp_path,
                                                                      monkeypatch, capsys):
    """install 里通常会直接把 key 写进工具的配置文件 —— 命令原样打日志就是把凭证留在日志里。"""
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    seen = {}

    def fake_run(argv, *, cwd, timeout):
        seen.setdefault("argv", []).append(argv)
        return 0, '{"found": false, "findings": []}', "", 0.1

    monkeypatch.setattr(runner, "_run_command", fake_run)
    outcome = runner.Outcome()
    recipe = _recipe([sys.executable, "-c", "print(1)", "{llm_model}"],
                     install=["echo {llm_api_key}"])
    runner.execute(_run(), recipe, [_packet("s_0001", "x\n")], tmp_path, {}, outcome,
                   llm=_llm())

    assert seen["argv"][0][-1] == "echo caev1_test-token"
    assert seen["argv"][1][-1] == "chat-primary"
    assert "caev1_test-token" not in capsys.readouterr().out


def test_a_recipe_that_copied_the_token_is_refused(runner):
    """recipe 会被冻结/复用/在页面上展示 —— 令牌进去就等于下一轮还在用这一轮的凭证。"""
    with pytest.raises(RuntimeError):
        runner._reject_secret({"notes": "api_key=caev1_test-token"}, _llm())
    # 占位符写法不受影响
    runner._reject_secret({"invoke": ["tool", "--key", "{llm_api_key}"]}, _llm())


def test_llm_env_is_cleared_when_this_run_has_no_token(runner, monkeypatch):
    monkeypatch.delenv("EVAL_LLM_TOKEN", raising=False)
    runner.apply_llm_env(_llm())
    assert runner.os.environ["EVAL_LLM_TOKEN"] == "caev1_test-token"
    # 下一轮没发令牌时必须清掉: 留着就是把上一轮的凭证交给了这一轮的工具
    runner.apply_llm_env({})
    assert "EVAL_LLM_TOKEN" not in runner.os.environ
    assert "EVAL_LLM_BASE_URL" not in runner.os.environ


# ── execute ──────────────────────────────────────────────────────────────────

def _recipe(argv: list[str], **over) -> dict:
    base = {"tool_version": "t1", "invoke": argv, "output_parser": {"kind": "json_stdout"},
            "timeout_seconds": 30}
    base.update(over)
    return base


def _run(repeats: int = 1) -> dict:
    return {"run_id": 7, "item_id": 1, "repeats": repeats}


ECHO_JSON = [sys.executable, "-c",
             "import json,sys;print(json.dumps({'found': True, 'findings': [],"
             " 'file': sys.argv[1]}))", "{sample_file}"]


def test_execute_collects_raw_and_translated(runner, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runner, "deliver",
                        lambda rid, answers: calls.append({k: list(v) for k, v in answers.items()}))
    outcome = runner.Outcome()
    packets = [_packet("s_0001", "print(1)\n")]

    runner.execute(_run(repeats=2), _recipe(ECHO_JSON), packets, tmp_path, {}, outcome)

    assert outcome.calls == 2 and outcome.failures == 0
    delivered = outcome.answers["s_0001"]
    assert len(delivered) == 2
    assert json.loads(delivered[0]["raw"])["found"] is True     # 原生输出原样
    assert delivered[0]["answer"]["found"] is True              # 翻译结果单独一份
    # 每次交的都是**这个样本到目前为止的全部轮次**, 否则平台会把第 2 轮当成第 1 轮覆盖
    assert [len(call["s_0001"]) for call in calls] == [1, 2]


def test_budget_stop_keeps_the_answers_already_produced(runner, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    outcome = runner.Outcome()
    packets = [_packet(f"s_{i:04d}", "print(1)\n") for i in range(1, 5)]

    with pytest.raises(runner.BudgetExceeded):
        runner.execute(_run(repeats=1), _recipe(ECHO_JSON), packets, tmp_path,
                       {"max_model_calls": 2}, outcome)

    assert outcome.calls == 2
    assert len(outcome.answers) == 2      # 跑出来的两个不能丢


def test_wall_clock_stop_also_counts_as_budget(runner, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    outcome = runner.Outcome()
    outcome.started -= 10_000            # 假装已经跑了很久
    with pytest.raises(runner.BudgetExceeded):
        runner.execute(_run(), _recipe(ECHO_JSON), [_packet("s_0001", "x\n")],
                       tmp_path, {"max_seconds": 1}, outcome)


def test_tampered_sample_is_a_dataset_error_not_a_tool_failure(runner, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    packet = _packet("s_0001", "print(1)\n")
    packet["artifact_hash"] = "0" * 64    # 数据集被改过
    with pytest.raises(runner.DatasetError):
        runner.execute(_run(), _recipe(ECHO_JSON), [packet], tmp_path, {}, runner.Outcome())


def test_crashing_tool_still_leaves_its_stderr_as_raw(runner, tmp_path, monkeypatch):
    """工具崩在 stderr 时, 库里不能只剩一个空字符串 —— 那是"查不出原因"的开始。"""
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    outcome = runner.Outcome()
    boom = [sys.executable, "-c", "import sys;sys.stderr.write('boom');sys.exit(2)"]
    runner.execute(_run(), _recipe(boom), [_packet("s_0001", "x\n")], tmp_path, {}, outcome)
    delivered = outcome.answers["s_0001"][0]
    assert delivered["raw"] == "boom"
    assert delivered["answer"] is None     # 没有 JSON → 翻译失败, 判分算 invalid_output
    assert outcome.failures == 1


# ── D4-5: 工具自报「这类样本我不覆盖」 ──────────────────────────────────────────

def test_exclude_codes_are_declared_not_guessed(runner):
    """`exclude_exit_codes` 两种写法都要认; 没写 = 一条都不排除。"""
    assert runner.exclude_reason({}, 0) is None
    assert runner.exclude_reason({}, 3) is None
    assert runner.exclude_reason({"exclude_exit_codes": [3]}, 3) == "rc=3"
    assert runner.exclude_reason({"exclude_exit_codes": [3]}, 0) is None
    # 带原因时报表才能按原因分组("语言不支持"和"平台不支持"是两件事)
    assert runner.exclude_reason(
        {"exclude_exit_codes": {"3": "language_not_supported"}}, 3) == "language_not_supported"
    # 超时永远不是"不覆盖": 跑不完 ≠ 不支持
    assert runner.exclude_reason({"exclude_exit_codes": [124]}, 124) is None


def test_excluded_sample_is_delivered_as_excluded_not_as_a_failure(runner, tmp_path, monkeypatch):
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    outcome = runner.Outcome()
    unsupported = [sys.executable, "-c",
                   "import sys;sys.stderr.write('no parser for this language');sys.exit(3)"]

    runner.execute(_run(repeats=2), _recipe(unsupported, exclude_exit_codes=[3]),
                   [_packet("s_0001", "x\n")], tmp_path, {}, outcome)

    assert outcome.excluded == 2
    assert outcome.failures == 0        # 不是一次失败的调用, 是这条样本压根不归它管
    delivered = outcome.answers["s_0001"]
    assert [d["excluded"] for d in delivered] == ["rc=3", "rc=3"]
    assert all(d["answer"] is None for d in delivered)
    # 原生输出仍然留着: “它到底说了什么”是可查的
    assert "no parser" in delivered[0]["raw"]


def test_without_the_declaration_the_same_exit_code_is_a_plain_failure(runner, tmp_path,
                                                                      monkeypatch):
    """同一条命令、同一个退出码: 没声明就是一次失败的调用 —— 声明不是橡皮图章。"""
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    outcome = runner.Outcome()
    unsupported = [sys.executable, "-c", "import sys;sys.exit(3)"]
    runner.execute(_run(), _recipe(unsupported), [_packet("s_0001", "x\n")],
                   tmp_path, {}, outcome)
    assert outcome.failures == 1 and outcome.excluded == 0
    assert "excluded" not in outcome.answers["s_0001"][0]


def test_no_recipe_is_a_refusal_not_a_guess(runner, monkeypatch, tmp_path):
    finished = []
    monkeypatch.setattr(runner, "finish", lambda rid, status, **kw: finished.append((status, kw)))
    monkeypatch.setattr(runner, "WORK_ROOT", tmp_path)
    monkeypatch.setattr(runner, "FALLBACK_RECIPE", "")
    # 关掉就地适配: 这一条守的是"宁可不做, 也不拿默认参数硬跑"
    monkeypatch.setattr(runner, "ADAPTER_ENABLED", False)

    runner.run_once({"run": {"run_id": 9, "item_id": 42, "repeats": 3, "budget": {}},
                     "recipe": None, "samples": [_packet("s_0001", "x\n")]})

    assert finished[0][0] == "failed"
    assert finished[0][1]["failure_reason"] == "no_recipe"


def test_adaptation_failure_becomes_a_terminal_state(runner, monkeypatch, tmp_path):
    """探不通就是终态(R9), 不许无限重试, 也不许落成 success。"""
    finished = []
    monkeypatch.setattr(runner, "finish", lambda rid, status, **kw: finished.append((status, kw)))
    monkeypatch.setattr(runner, "WORK_ROOT", tmp_path)
    monkeypatch.setattr(runner, "ADAPTER_ENABLED", True)
    monkeypatch.setattr(runner, "_tool_dir", lambda run, claimed: tmp_path / "tool")
    (tmp_path / "tool").mkdir()
    monkeypatch.setattr(runner, "_adapt",
                        lambda *a, **k: (None, "needs_paid_key", {"steps": 3}))

    runner.run_once({"run": {"run_id": 10, "item_id": 5, "repeats": 1, "budget": {}},
                     "recipe": None, "samples": [_packet("s_0001", "x\n")]})

    assert finished[0][0] == "failed"
    assert finished[0][1]["failure_reason"] == "needs_paid_key"
    assert finished[0][1]["cost"]["adapt"] == {"steps": 3}


def test_exhausted_model_budget_is_not_blamed_on_the_tool(runner, monkeypatch, tmp_path):
    """适配阶段把这一轮的模型预算花完, 要落 `model_budget_exceeded`。

    记成 `agent_gave_up` 会让报表读成"这个工具适配不了", 而真实原因是预算设小了 ——
    两者的处置完全不同(换工具 vs 调预算)。
    """
    from ai4sec_platform.domains.capabilities.eval.store import FAILURE_REASONS

    class _Adapter:
        class AdapterBudgetError(RuntimeError):
            pass

        @staticmethod
        def adapt(**kwargs):
            raise _Adapter.AdapterBudgetError("模型代理 429: 调用次数已用尽 (400/400)")

    monkeypatch.setattr(runner, "_load_adapter", lambda: _Adapter)
    packet = {"sample_key": "s_0001", "file_name": "x.py", "relative_path": "x.py"}
    recipe, failure, detail = runner._adapt(
        {"run_id": 13, "item_id": 8}, tmp_path, tmp_path, tmp_path,
        [packet], runner.Outcome())

    assert recipe is None
    assert failure == "model_budget_exceeded"
    assert failure in FAILURE_REASONS       # 枚举里真有这个值, 否则页面归不了类
    assert "429" in detail["detail"]


def test_missing_tool_repo_is_repo_unavailable(runner, monkeypatch, tmp_path):
    finished = []
    monkeypatch.setattr(runner, "finish", lambda rid, status, **kw: finished.append((status, kw)))
    monkeypatch.setattr(runner, "WORK_ROOT", tmp_path)
    monkeypatch.setattr(runner, "ADAPTER_ENABLED", True)
    monkeypatch.setattr(runner, "_tool_dir", lambda run, claimed: None)

    runner.run_once({"run": {"run_id": 11, "item_id": 6, "repeats": 1, "budget": {}},
                     "recipe": None, "samples": [_packet("s_0001", "x\n")]})

    assert finished[0][1]["failure_reason"] == "repo_unavailable"


# ── 冻结 recipe 那条路(不经过适配) ───────────────────────────────────────────

def test_tool_dir_is_only_fetched_when_the_recipe_asks_for_it(runner):
    """`{tool_dir}` 不在命令里就不克隆 —— 版本号有别的来源, 而 21 MB 源码白拉一遍
    只会让"这轮为什么慢"变成查不明白的问题。"""
    assert runner._recipe_needs_tool_dir({"install": ["pip install {tool_dir}/core"]})
    assert runner._recipe_needs_tool_dir({"invoke": ["python3", "{tool_dir}/scan.py"]})
    assert not runner._recipe_needs_tool_dir({"install": ["pip install openant"],
                                              "invoke": ["openant", "scan"]})


def test_frozen_recipe_takes_the_version_from_disk_not_from_the_frozen_sha(runner,
                                                                          monkeypatch, tmp_path):
    """冻结时抄的 sha 会过期: runner 只能 `git clone --branch`, 而工具仓库往往连 tag/release
    都没有(OpenAnt 实测皆空), 只能跟 master。版本号留旧值 = 两次不同版本的运行被当成同一版本。"""
    tool_dir = tmp_path / "tool"
    tool_dir.mkdir()

    class _Adapter:
        @staticmethod
        def _tool_version(path):
            return "git:9143061f93c5", "git"

    monkeypatch.setattr(runner, "_load_adapter", lambda: _Adapter)
    outcome = runner.Outcome()
    recipe = runner._stamp_runtime_version(
        {"tool_version": "git:deadbeef", "tool_version_source": "stamp_version"},
        tool_dir, outcome)

    assert recipe["tool_version"] == "git:9143061f93c5"
    assert "deadbeef" in recipe["tool_version_source"]
    assert any("tool_version" in n for n in outcome.notes)


def test_unreadable_version_does_not_kill_the_run(runner, monkeypatch, tmp_path):
    """读不出 HEAD(目录不是 git 仓、git 报错)时沿用冻结值并留痕 —— 版本号是元数据,
    不能因为它让一整轮 20 对样本白跑。"""
    tool_dir = tmp_path / "tool"
    tool_dir.mkdir()

    def boom(_):
        raise OSError("git not found")

    class _Adapter:
        _tool_version = staticmethod(boom)

    monkeypatch.setattr(runner, "_load_adapter", lambda: _Adapter)
    outcome = runner.Outcome()
    recipe = runner._stamp_runtime_version({"tool_version": "git:deadbeef"},
                                           tool_dir, outcome)

    assert recipe["tool_version"] == "git:deadbeef"
    assert any("读不出来" in n for n in outcome.notes)


def test_a_frozen_recipe_still_gets_the_tool_source_it_references(runner, monkeypatch, tmp_path):
    """手冻的 recipe 不经过适配路径, 没人替它克隆 —— 而 `{tool_dir}` 正是 install 的输入。
    不补这一步, 每一轮都以 install_failed 收场, 而报错看起来像"工具装不上"。"""
    finished, cloned = [], []
    monkeypatch.setattr(runner, "finish", lambda rid, status, **kw: finished.append((status, kw)))
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    monkeypatch.setattr(runner, "WORK_ROOT", tmp_path / "runs")
    monkeypatch.setattr(runner, "TOOL_ROOT", tmp_path / "tools")
    (tmp_path / "runs").mkdir()

    def fake_tool_dir(run, claimed):
        cloned.append(run["item_id"])
        path = tmp_path / "tools" / f"item-{run['item_id']}"
        path.mkdir(parents=True)
        return path

    monkeypatch.setattr(runner, "_tool_dir", fake_tool_dir)

    recipe = {"tool_version": "v1", "install": ["test -d {tool_dir}"],
              "invoke": ["python3", "-c", "print('{}')"], "output_parser": "json"}
    runner.run_once({"run": {"run_id": 12, "item_id": 7, "repeats": 1, "budget": {}},
                     "recipe": {"recipe": recipe, "tool_version": "v1"},
                     "samples": [_packet("s_0001", "x\n")]})

    assert cloned == [7]
    assert finished and finished[0][0] == "success"


# ── D3: 解析器 ────────────────────────────────────────────────────────────────

SARIF = json.dumps({"runs": [{"results": [
    {"ruleId": "CWE-89", "message": {"text": "SQL injection"},
     "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/models.py"},
                                         "region": {"startLine": 171, "endLine": 173}}}]}]}]})


def test_sarif_is_parsed_structurally_not_translated(runner):
    answer, why = runner.parse_answer("sarif", SARIF, returncode=0)
    assert why == ""
    assert answer == {"found": True, "findings": [{
        "file": "app/models.py", "function": "", "line_start": 171, "line_end": 173,
        "type_cwe": "CWE-89", "evidence": "SQL injection"}]}


def test_sarif_with_no_results_is_a_true_negative(runner):
    answer, _ = runner.parse_answer("sarif", json.dumps({"runs": [{"results": []}]}), returncode=0)
    assert answer == {"found": False, "findings": []}


def test_sarif_rule_id_that_is_not_a_cwe_is_not_invented_into_one(runner):
    payload = {"runs": [{"results": [{"ruleId": "py/sql-injection", "locations": [
        {"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                              "region": {"startLine": 3}}}]}]}]}
    answer, _ = runner.parse_answer("sarif", json.dumps(payload), returncode=0)
    assert answer["findings"][0]["type_cwe"] is None


def test_agent_translate_can_refuse_and_that_is_not_a_verdict(runner):
    """模型翻不出来时返回 None → 判分算 invalid_output。不许替工具答 found=false。"""
    assert runner.parse_answer("agent_translate", "prose", returncode=0,
                               translate=lambda raw, ctx, rc: None) == (None, "translate_failed")

    def translated(raw, ctx, rc):
        return {"found": True, "findings": []}
    answer, why = runner.parse_answer("agent_translate", "prose", returncode=0, translate=translated)
    assert answer == {"found": True, "findings": []} and why == ""


def test_string_and_dict_parsers_are_the_same_thing(runner):
    raw = '{"found": false, "findings": []}'
    assert runner.parse_answer("json", raw, returncode=0)[0] == \
        runner.parse_answer({"kind": "json"}, raw, returncode=0)[0]
    # 老 recipe 里的 json_stdout 仍然认(库里已有的配置不能因为改名失效)
    assert runner.parse_answer({"kind": "json_stdout"}, raw, returncode=0)[0]["found"] is False


# ── D2: HTTP 形态 ─────────────────────────────────────────────────────────────

def test_render_tree_only_touches_string_leaves(runner):
    body = {"code": "{sample_content}", "path": "{relative_path}", "n": 3,
            "nested": [{"k": "{sample_key}"}]}
    out = runner._render_tree(body, {"sample_content": "print(1)", "relative_path": "a.py",
                                     "sample_key": "s_0001"})
    assert out == {"code": "print(1)", "path": "a.py", "n": 3, "nested": [{"k": "s_0001"}]}


def test_http_invoke_maps_status_to_exit_code(runner, tmp_path, monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    seen = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            seen["body"] = json.loads(self.rfile.read(length) or b"{}")
            payload = json.dumps({"found": True, "findings": []}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        spec = {"method": "POST", "url": f"http://127.0.0.1:{server.server_port}/scan",
                "body": {"code": "{sample_content}"}}
        code, out, err, _ = runner._http_invoke(
            spec, {"sample_content": "print(1)"}, timeout=10)
    finally:
        server.shutdown()

    assert code == 0 and err == "" and json.loads(out)["found"] is True
    assert seen["body"] == {"code": "print(1)"}   # 占位符换成了正文, 不是路径


def test_adaptation_that_succeeds_continues_into_the_evaluation(runner, monkeypatch, tmp_path):
    """探通之后**同一个 run 接着跑**, 不是再排一轮 —— 否则第一次调用永远拿不到结果。"""
    finished = []
    monkeypatch.setattr(runner, "finish", lambda rid, status, **kw: finished.append((status, kw)))
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    monkeypatch.setattr(runner, "WORK_ROOT", tmp_path)
    monkeypatch.setattr(runner, "ADAPTER_ENABLED", True)
    (tmp_path / "tool").mkdir()
    monkeypatch.setattr(runner, "_tool_dir", lambda run, claimed: tmp_path / "tool")
    recipe = {"tool_version": "v1", "output_parser": {"kind": "json"}, "invoke": ECHO_JSON}
    monkeypatch.setattr(runner, "_adapt", lambda *a, **k: (recipe, "adapted:v1", {"steps": 2}))

    runner.run_once({"run": {"run_id": 12, "item_id": 7, "repeats": 1, "budget": {}},
                     "recipe": None, "samples": [_packet("s_0001", "x\n")]})

    assert finished[0][0] == "success"
    assert finished[0][1]["cost"]["recipe_source"] == "adapted:v1"
    # 成功即回收工作目录(C6): recipe 与原生输出都已经在平台侧
    assert not any(tmp_path.glob("run-12-*"))


def test_every_run_records_peak_memory_and_cpu(runner):
    """PRD §12 第 12 条: 每次重放记峰值内存与 CPU。

    10-29 那次"评测把容器撑爆、复现页全 502"事后只能靠人回忆, 就是因为没有这组数。
    CPU 必须能按轮算(差值), 峰值只能取高水位 —— 两者在 cost 里标清楚, 别混成一个数。
    """
    outcome = runner.Outcome()
    cost = runner._cost({"item_id": 1}, outcome, {"tool_version": "v1"}, "adapted:v1",
                        Path("/tmp/x"))

    res = cost["resources"]
    for key in ("children_cpu_seconds", "runner_cpu_seconds",
                "children_max_rss_mb", "runner_peak_rss_mb", "peak_note"):
        assert key in res
    # 差值不会为负; 峰值在本进程里一定 > 0(解释器本身就要几 MB)
    assert res["children_cpu_seconds"] >= 0 and res["runner_cpu_seconds"] >= 0
    assert res["runner_peak_rss_mb"] is None or res["runner_peak_rss_mb"] > 0
    assert "生命周期" in res["peak_note"]


# ── 分数的来源(L4)────────────────────────────────────────────────────────────

def test_cost_records_which_model_produced_the_score(runner):
    """事后看一条分数, 除了"按哪份 recipe 跑的"还要能答"哪个模型跑的"。"""
    adapter = runner._load_adapter()
    adapter.reset_serving()
    adapter.record_serving("capability_eval_adapter", {
        "serving": {"upstream_model": "openai/deepseek-v4-flash", "upstream_group": "chat-primary",
                    "upstream_api_base": "https://volc.example/v1",
                    "source": "gateway_header", "attempted_fallbacks": 0},
        "usage": {"total_tokens": 42},
    })

    cost = runner._cost({"item_id": 1}, None, {"tool_version": "v1"}, "db:v1", Path("/tmp/x"))

    assert cost["model_serving"]["models"] == {"openai/deepseek-v4-flash": 1}
    assert cost["model_serving"]["consistent"] is True
    assert cost["model_serving"]["tokens"]["total_tokens"] == 42
    # recipe 来源与模型来源都在同一个 cost_json 里, 一条记录就能回答两个问题
    assert cost["recipe_source"] == "db:v1"


# ── 工具目录的占位符(D4-2)────────────────────────────────────────────────────

def test_tool_dir_placeholder_reaches_install_and_invoke(runner, tmp_path, monkeypatch):
    """install 要装的是**这个工具**的源码, 而目录名带 item 号。

    写死绝对路径的话, 同一份 recipe 换个工具就作废 —— 而 recipe 是按工具版本冻结的,
    它必须能自己算出工具在哪。
    """
    monkeypatch.setattr(runner, "deliver", lambda rid, answers: None)
    monkeypatch.setattr(runner, "TOOL_ROOT", tmp_path / "tools")
    seen = tmp_path / "install-saw.txt"
    install = "printf '%s' '{tool_dir}' > " + str(seen)
    invoke = [sys.executable, "-c",
              "import json,sys;print(json.dumps({'found': False, 'findings': [],"
              " 'tool_dir': sys.argv[1]}))", "{tool_dir}"]

    outcome = runner.Outcome()
    runner.execute(_run(), _recipe(invoke, install=[install]), [_packet("s_0001", "x\n")],
                   tmp_path, {}, outcome)

    expected = str(tmp_path / "tools" / "item-1")
    assert seen.read_text(encoding="utf-8") == expected
    assert outcome.answers["s_0001"][0]["answer"]["tool_dir"] == expected
