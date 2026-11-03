"""适配 agent(`deploy/eval/adapter.py`)的行为(D1/D2)。

这个文件守的不是"agent 聪不聪明", 而是几件**不管模型多聪明都不能破**的事:

  · 交上来的 recipe 必须是真跑通的 —— 没跑过 smoke 的配置不许入库;
  · 命令不能读到工具目录以外的东西, 也不能碰真值文件;
  · 写死答案的 invoke 要被拒(否则分数是人给的, 不是工具算的);
  · 平台故障不能被记成"工具无法适配"。
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

EVAL_DIR = Path(__file__).resolve().parents[2] / "deploy" / "eval"


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, EVAL_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def adapter():
    return _load("cap_eval_adapter", "adapter.py")


@pytest.fixture(scope="module")
def runner():
    return _load("cap_eval_runner_for_adapter", "runner.py")


def _sample(tmp_path: Path) -> dict:
    code = tmp_path / "code.py"
    code.write_text("import os\nos.system(sys.argv[1])\n", encoding="utf-8")
    return {"sample_key": "s_0001", "file": code, "relative_path": "app/run.py"}


# ── recipe 结构 ───────────────────────────────────────────────────────────────

def test_a_workable_recipe_has_no_problems(adapter):
    problems = adapter.validate_recipe({
        "tool_version": "v1", "install": ["pip install -e ."],
        "invoke": ["./audit", "--file", "{sample_file}"],
        "output_parser": {"kind": "json"}, "needs_host_agent": False})
    assert problems == []


def test_writing_the_answer_into_the_command_is_rejected(adapter):
    """把答案写进 invoke = 分数是人给的。这是最容易"看起来跑通"的作弊形态。"""
    problems = adapter.validate_recipe({
        "tool_version": "v1", "invoke": ["bash", "-c", "echo '{\"found\": false}'"],
        "output_parser": {"kind": "json"}})
    assert any("写死的答案" in p for p in problems)


def test_missing_invoke_or_version_is_rejected(adapter):
    assert any("tool_version" in p for p in adapter.validate_recipe(
        {"invoke": ["x"], "output_parser": {"kind": "json"}}))
    assert any("至少要有一个" in p for p in adapter.validate_recipe(
        {"tool_version": "v1", "output_parser": {"kind": "json"}}))


def test_host_agent_without_a_host_model_is_rejected(adapter):
    problems = adapter.validate_recipe({
        "tool_version": "v1", "invoke": ["x"], "output_parser": "json",
        "needs_host_agent": True, "host_model": None})
    assert any("host_model" in p for p in problems)


def test_unknown_parser_is_rejected(adapter):
    assert any("output_parser" in p for p in adapter.validate_recipe(
        {"tool_version": "v1", "invoke": ["x"], "output_parser": "vibes"}))


def test_a_placeholder_version_is_replaced_by_a_real_fingerprint(adapter, tmp_path):
    """模型写 unknown 时不能让两个版本的配置挤成同一行 —— 那会让旧的无声消失。"""
    tool = tmp_path / "tool"
    tool.mkdir()
    (tool / "audit.py").write_text("print(1)\n", encoding="utf-8")
    recipe = {"tool_version": "unknown", "invoke": ["x"], "output_parser": "json"}

    stamped = adapter.stamp_version(recipe, tool)

    assert stamped["tool_version"].startswith("tree:")
    assert stamped["tool_version_source"].startswith("tree")
    assert recipe["tool_version"] == "unknown"      # 不改调用方手里的对象


def test_a_version_the_model_actually_found_is_kept(adapter, tmp_path):
    tool = tmp_path / "tool"
    tool.mkdir()
    assert adapter.stamp_version({"tool_version": "v1.2.3"}, tool)["tool_version"] == "v1.2.3"


def test_render_argv_agrees_with_the_runner(adapter, runner):
    """两处各有一份 8 行的占位符替换(执行位要能单独起)。这里锁住它们不许漂。"""
    argv = ["scan", "--file", "{sample_file}", "--path", "{relative_path}", " "]
    values = {"sample_file": "/tmp/a b.py", "relative_path": "app/x.py"}
    assert adapter.render_argv(argv, values) == runner.render(argv, values)


# ── 边界 ──────────────────────────────────────────────────────────────────────

def test_read_file_cannot_escape_the_tool_dir(adapter, tmp_path):
    tool = tmp_path / "tool"
    tool.mkdir()
    (tool / "ok.txt").write_text("fine", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("nope", encoding="utf-8")
    assert adapter.read_file(tool, "ok.txt") == "fine"
    assert "拒绝" in adapter.read_file(tool, "../secret.txt")


def test_commands_touching_truth_are_refused(adapter, tmp_path):
    result = adapter.run_shell("cat truth/s_0001.json", tmp_path)
    assert result["rc"] != 0 and "拒绝" in result["output"]


def test_shell_env_does_not_leak_the_eval_token(adapter, monkeypatch):
    monkeypatch.setenv("EVAL_TOKEN", "secret-token")
    monkeypatch.setenv("PATH", "/usr/bin")
    env = adapter._shell_env()
    assert "EVAL_TOKEN" not in env
    assert env["PATH"] == "/usr/bin"


def test_shell_env_does_hand_over_the_run_model_token(adapter, monkeypatch):
    """L5 的令牌是**特意**发给这一轮工具的东西: 不给它, 需要模型的工具根本适配不了。
    它与 `EVAL_TOKEN`(平台的内部调用凭证)是两回事, 剥掉后者不能连前者一起剥。"""
    monkeypatch.setenv("EVAL_TOKEN", "secret-token")
    monkeypatch.setenv("EVAL_LLM_TOKEN", "caev1_run-token")
    monkeypatch.setenv("EVAL_LLM_BASE_URL", "http://ai4sec:8100/api/internal/eval/v1")
    monkeypatch.setenv("EVAL_LLM_MODEL", "chat-primary")
    env = adapter._shell_env()
    assert env["EVAL_LLM_TOKEN"] == "caev1_run-token"
    assert env["EVAL_LLM_MODEL"] == "chat-primary"
    assert "EVAL_TOKEN" not in env


# ── smoke: 交上去之前必须真跑 ─────────────────────────────────────────────────

def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code, "{sample_file}", "{relative_path}"]


def test_smoke_passes_only_when_the_command_really_runs(adapter, tmp_path):
    sample = _sample(tmp_path)
    good = {"tool_version": "v1", "output_parser": {"kind": "json"},
            "invoke": _py("import json,sys;print(json.dumps({'found': True, 'findings': [],"
                          " 'file': sys.argv[2]}))")}
    ok, why = adapter.smoke(good, sample=sample, workdir=tmp_path)
    assert ok and why == ""

    crash = {"tool_version": "v1", "output_parser": {"kind": "json"},
             "invoke": _py("import sys;sys.exit(3)")}
    ok, why = adapter.smoke(crash, sample=sample, workdir=tmp_path)
    assert not ok and "退出码 3" in why


def test_silent_tool_is_no_output_not_a_clean_file(adapter, tmp_path):
    """能跑但一个字不说 ≠ 没发现问题。"""
    silent = {"tool_version": "v1", "output_parser": {"kind": "json"},
              "invoke": _py("pass")}
    ok, why = adapter.smoke(silent, sample=_sample(tmp_path), workdir=tmp_path)
    assert not ok and "无输出" in why


def test_smoke_rejects_output_that_cannot_become_a_contract_answer(adapter, tmp_path):
    prose = {"tool_version": "v1", "output_parser": {"kind": "json"},
             "invoke": _py("print('looks fine to me')")}
    ok, why = adapter.smoke(prose, sample=_sample(tmp_path), workdir=tmp_path)
    assert not ok and "解析不出" in why


# ── 退出码语义与 recipe 自带文件(D4: 2026-11-02 拿 OpenAnt 实测出来的两个洞) ────

def test_exit_code_semantics_are_declared_by_the_recipe(adapter):
    """默认只有 0 算成功; 扫描器自报的语义写进 `ok_exit_codes`, 不靠我们猜。

    OpenAnt 明写 0=干净 / 1=有发现 / 2=跑挂, 且 README 专门警告过 CI 会把它误判成失败。
    """
    assert adapter.exit_ok({}, 0) is True
    assert adapter.exit_ok({}, 1) is False
    assert adapter.exit_ok({"ok_exit_codes": [0, 1]}, 1) is True
    # 超时是被我们杀掉的, 不是工具给的结论 —— 声明也救不回来
    assert adapter.exit_ok({"ok_exit_codes": [0, 1, 124]}, 124) is False


def test_a_bad_ok_exit_codes_is_rejected_at_intake(adapter):
    base = {"tool_version": "v1", "invoke": ["./audit"], "output_parser": {"kind": "json"}}
    assert adapter.validate_recipe(dict(base, ok_exit_codes=[0, 1])) == []
    for bad in (["1"], [True], [], "0", [0, 124]):
        assert adapter.validate_recipe(dict(base, ok_exit_codes=bad)), bad


def test_a_bad_exclude_declaration_is_rejected_at_intake(adapter):
    """写错格式的"不覆盖"声明等于没写: 没覆盖会被重新记成没找到, 而报表上看不出来。"""
    base = {"tool_version": "v1", "invoke": ["./audit"], "output_parser": {"kind": "json"}}
    assert adapter.validate_recipe(dict(base, exclude_exit_codes=[3])) == []
    assert adapter.validate_recipe(
        dict(base, exclude_exit_codes={"3": "language_not_supported"})) == []
    for bad in (["3"], [True], [], "3", {"3": ""}, {"x": "y"}, {"124": "timeout"}, [124]):
        assert adapter.validate_recipe(dict(base, exclude_exit_codes=bad)), bad


def test_smoke_accepts_a_findings_exit_code_when_declared(adapter, tmp_path):
    recipe = {"tool_version": "v1", "output_parser": {"kind": "json"},
              "invoke": _py("import json,sys;print(json.dumps({'found': True, 'findings': []}));"
                            "sys.exit(1)")}
    ok, why = adapter.smoke(recipe, sample=_sample(tmp_path), workdir=tmp_path)
    assert not ok and "退出码 1" in why

    ok, why = adapter.smoke(dict(recipe, ok_exit_codes=[0, 1]),
                            sample=_sample(tmp_path), workdir=tmp_path)
    assert ok, why


def test_a_recipe_carrying_the_model_token_is_rejected_at_intake(adapter):
    """适配 agent 很自然地会把"刚才跑通的那条命令"照抄进 recipe —— 而那条命令里
    可能带着令牌的真值。recipe 会被冻结和展示, 令牌进去就是泄漏。"""
    base = {"tool_version": "v1", "invoke": ["./audit"], "output_parser": {"kind": "json"}}
    assert adapter.validate_recipe(
        dict(base, invoke=["./audit", "--key", "{llm_api_key}"])) == []
    assert any("令牌" in p for p in adapter.validate_recipe(
        dict(base, invoke=["./audit", "--key", "caev1_leaked"])))


def test_recipe_files_must_stay_inside_the_workdir(adapter):
    base = {"tool_version": "v1", "invoke": ["./audit"], "output_parser": {"kind": "json"}}
    assert adapter.validate_recipe(dict(base, files={"shim.py": "print(1)"})) == []
    for bad in ({"/etc/x": "x"}, {"../x": "x"}, {"a.py": 1}, ["a"]):
        assert adapter.validate_recipe(dict(base, files=bad)), bad


def test_adapter_and_runner_agree_on_exit_codes(adapter, runner):
    """两处各留一份实现, 分歧会让"自检过了、实跑记失败"这种事发生。"""
    table = [({}, 0), ({}, 1), ({"ok_exit_codes": [0, 1]}, 1), ({"ok_exit_codes": [0, 1]}, 2),
             ({"ok_exit_codes": [0, 1]}, 124), ({"ok_exit_codes": [2]}, 2)]
    for recipe, code in table:
        assert adapter.exit_ok(recipe, code) == runner.exit_ok(recipe, code), (recipe, code)


def test_adapter_and_runner_agree_on_excluded_codes(adapter, runner):
    table = [({}, 3), ({"exclude_exit_codes": [3]}, 3), ({"exclude_exit_codes": [3]}, 0),
             ({"exclude_exit_codes": {"3": "language_not_supported"}}, 3),
             ({"exclude_exit_codes": {"3": "language_not_supported"}}, 4),
             ({"exclude_exit_codes": [124]}, 124)]
    for recipe, code in table:
        assert (adapter.exclude_reason(recipe, code)
                == runner.exclude_reason(recipe, code)), (recipe, code)


def test_smoke_refuses_when_the_sample_itself_is_declared_out_of_scope(adapter, tmp_path):
    """自检的样本就是工具必须能审的那一个。它被声明成"不覆盖", 说明这份 recipe 不成立。"""
    recipe = {"tool_version": "v1", "output_parser": {"kind": "json"},
              "exclude_exit_codes": {"3": "language_not_supported"},
              "invoke": _py("import sys;sys.exit(3)")}
    ok, why = adapter.smoke(recipe, sample=_sample(tmp_path), workdir=tmp_path)
    assert not ok
    assert "不覆盖" in why and "language_not_supported" in why


# ── 主循环 ────────────────────────────────────────────────────────────────────

def _asker(replies):
    calls = []

    def ask(profile, prompt, payload):
        calls.append(payload)
        return replies[min(len(calls) - 1, len(replies) - 1)]
    ask.calls = calls
    return ask


def test_adapt_returns_a_recipe_only_after_it_runs(adapter, tmp_path):
    tool = tmp_path / "tool"
    tool.mkdir()
    (tool / "README.md").write_text("audit tool", encoding="utf-8")
    sample = _sample(tmp_path)
    ask = _asker([
        {"action": "bash", "command": "ls"},
        {"action": "recipe", "recipe": {
            "tool_version": "v1", "output_parser": {"kind": "json"},
            "invoke": _py("import json,sys;print(json.dumps({'found': False,"
                          " 'findings': [], 'file': sys.argv[2]}))")}},
    ])

    recipe, source, detail = adapter.adapt(
        run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool, sample=sample,
        workdir=tmp_path, ask_fn=ask, freeze=False)

    assert recipe is not None and source == "adapted:v1"
    assert detail == {"steps": 2, "smoke_sample": "s_0001"}
    # 第一次调用必须已经把目录内容给了模型, 否则它只能瞎猜
    assert ask.calls[0]["initial_snapshot"]["manifests"]["README.md"] == "audit tool"


def _mixed_pool(tmp_path: Path) -> list[dict]:
    """第一份是 C, 第二份是 Python —— 2026-11-03 run 5 的真实形状。"""
    c_file = tmp_path / "code.c"
    c_file.write_text("int main(void){return 0;}\n", encoding="utf-8")
    py_file = tmp_path / "code.py"
    py_file.write_text("import os\nos.system('id')\n", encoding="utf-8")
    return [{"sample_key": "s_0001", "file": c_file, "relative_path": "src/a.c"},
            {"sample_key": "s_0002", "file": py_file, "relative_path": "src/b.py"}]


def test_a_tool_covering_only_some_languages_can_still_be_adapted(adapter, tmp_path):
    """自检样本默认是第一份, 但 agent 可以点名换一份。

    2026-11-03 run 5 就死在这: 第一份样本是 C, 被测工具只认 `.py`, 于是
    "排除这条样本"(exclude_exit_codes)和"自检必须过"互相矛盾 —— 一个本来能评
    4 条 Python 样本的工具被判成「无法适配」。整批交给 agent 挑就够了。
    """
    tool = tmp_path / "tool"
    tool.mkdir()
    pool = _mixed_pool(tmp_path)
    invoke = _py("import json,sys;sys.exit(3) if not sys.argv[2].endswith('.py') "
                 "else print(json.dumps({'found': False, 'findings': [], 'file': sys.argv[2]}))")
    recipe = {"tool_version": "v1", "output_parser": {"kind": "json"}, "invoke": invoke,
              "ok_exit_codes": [0], "exclude_exit_codes": {"3": "language_not_supported"}}
    ask = _asker([{"action": "recipe", "recipe": recipe, "smoke_sample": "s_0002"}])

    got, source, detail = adapter.adapt(
        run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool,
        sample=pool[0], sample_pool=pool, workdir=tmp_path, ask_fn=ask, freeze=False)

    assert got is not None and source == "adapted:v1"
    assert detail["smoke_sample"] == "s_0002"
    # agent 得先看得见整批样本, 否则它没法知道还有别的语言可挑
    assert [s["sample_key"] for s in ask.calls[0]["sample_pool"]] == ["s_0001", "s_0002"]
    assert ask.calls[0]["sample_pool"][1]["file_name"] == "code.py"


def test_without_a_smoke_sample_the_first_one_is_still_used(adapter, tmp_path):
    """不给 `smoke_sample` 时行为与从前逐字一致 —— 老 recipe 不受影响。"""
    tool = tmp_path / "tool"
    tool.mkdir()
    pool = _mixed_pool(tmp_path)
    recipe = {"tool_version": "v1", "output_parser": {"kind": "json"},
              "invoke": _py("import json,sys;sys.exit(3) if not sys.argv[2].endswith('.py') "
                            "else print(json.dumps({'found': False, 'findings': []}))"),
              "exclude_exit_codes": {"3": "language_not_supported"}}
    ask = _asker([
        {"action": "recipe", "recipe": recipe},
        {"action": "give_up", "reason": "agent_gave_up", "detail": "只认 Python"},
    ])

    got, reason, _ = adapter.adapt(
        run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool,
        sample=pool[0], sample_pool=pool, workdir=tmp_path, ask_fn=ask, freeze=False)

    assert got is None and reason == "agent_gave_up"
    # 被拒的理由要能指向真正的原因, 不能只说"自检失败"
    assert "不覆盖" in ask.calls[1]["history"][-1]["result"]


def test_an_unknown_smoke_sample_is_bounced_instead_of_silently_ignored(adapter, tmp_path):
    tool = tmp_path / "tool"
    tool.mkdir()
    pool = _mixed_pool(tmp_path)
    ask = _asker([
        {"action": "recipe", "smoke_sample": "s_9999", "recipe": {
            "tool_version": "v1", "output_parser": {"kind": "json"},
            "invoke": _py("import json;print(json.dumps({'found': False, 'findings': []}))")}},
        {"action": "give_up", "reason": "agent_gave_up", "detail": "算了"},
    ])

    adapter.adapt(run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool,
                  sample=pool[0], sample_pool=pool, workdir=tmp_path, ask_fn=ask, freeze=False)

    assert "不在本轮样本里" in ask.calls[1]["history"][-1]["result"]


def test_adapt_stamps_the_version_before_freezing(adapter, tmp_path):
    """版本号要在 smoke 之前补齐, 否则落库时两份不同配置会共用一行 "unknown"。"""
    tool = tmp_path / "tool"
    tool.mkdir()
    ask = _asker([{"action": "recipe", "recipe": {
        "tool_version": "unknown", "output_parser": {"kind": "json"},
        "invoke": _py("import json;print(json.dumps({'found': False, 'findings': []}))")}}])

    recipe, source, _ = adapter.adapt(
        run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool,
        sample=_sample(tmp_path), workdir=tmp_path, ask_fn=ask, freeze=False)

    assert recipe["tool_version"].startswith("tree:")
    assert source.startswith("adapted:tree:")


def test_a_recipe_that_fails_smoke_is_bounced_back_not_accepted(adapter, tmp_path):
    tool = tmp_path / "tool"
    tool.mkdir()
    bad = {"tool_version": "v1", "output_parser": {"kind": "json"},
           "invoke": _py("import sys;sys.exit(2)")}
    ask = _asker([
        {"action": "recipe", "recipe": bad},
        {"action": "give_up", "reason": "install_failed", "detail": "跑不起来"},
    ])
    recipe, reason, _ = adapter.adapt(
        run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool,
        sample=_sample(tmp_path), workdir=tmp_path, ask_fn=ask, freeze=False)

    assert recipe is None and reason == "install_failed"
    # 第二次调用要带着"上次那份被拒了, 原因是自检失败", 不然模型会原样再交一遍
    assert "自检失败" in json.dumps(ask.calls[1]["history"], ensure_ascii=False)


def test_give_up_reason_outside_the_enum_falls_back_to_agent_gave_up(adapter, tmp_path):
    tool = tmp_path / "tool"
    tool.mkdir()
    _, reason, _ = adapter.adapt(
        run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool,
        sample=_sample(tmp_path), workdir=tmp_path, freeze=False,
        ask_fn=_asker([{"action": "give_up", "reason": "我觉得不行"}]))
    assert reason == "agent_gave_up"


def test_running_out_of_steps_is_a_timeout_not_a_silent_success(adapter, tmp_path, monkeypatch):
    tool = tmp_path / "tool"
    tool.mkdir()
    monkeypatch.setattr(adapter, "MAX_STEPS", 2)
    recipe, reason, detail = adapter.adapt(
        run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool,
        sample=_sample(tmp_path), workdir=tmp_path, freeze=False,
        ask_fn=_asker([{"action": "bash", "command": "true"}]))
    assert recipe is None and reason == "timeout" and detail["steps"] == 2


# ── 阶段提醒 ─────────────────────────────────────────────────────────────────

def test_the_read_budget_hint_changes_as_steps_burn(adapter):
    """提示词里的"读代码 ≤20 步"在 run 6/7 里都没被遵守, 所以每轮跟着 payload 递一句话。

    三档必须互相排斥且边界明确, 否则模型会同时收到"还能读"和"别再读了"。
    """
    early = adapter._phase_hint(3, 117)
    assert "还能读 17 步" in early and "不要再" not in early

    spent = adapter._phase_hint(21, 99)
    assert "预算已经用完" in spent and "sample.file" in spent

    closing = adapter._phase_hint(110, 10)
    assert "只剩 10 步" in closing and "recipe" in closing
    # 收口档优先于"读完了": 剩 10 步时唯一该说的是别读了赶紧交
    assert "不要再读任何源码" in closing


def test_the_hint_rides_along_with_every_step(adapter, tmp_path, monkeypatch):
    """它必须出现在**每一步**的 payload 里, 而不是只在第一步的 snapshot 里 ——
    run 7 的 45 步读码都发生在中段, 首步给一次等于没给。"""
    tool = tmp_path / "tool"
    tool.mkdir()
    monkeypatch.setattr(adapter, "MAX_STEPS", 5)
    ask = _asker([{"action": "bash", "command": "true"}] * 5)

    adapter.adapt(run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool,
                  sample=_sample(tmp_path), workdir=tmp_path, ask_fn=ask, freeze=False)

    hints = [c["phase_hint"] for c in ask.calls]
    assert len(hints) == 5 and all(hints)
    # MAX_STEPS=5 时第 1 步 steps_left=5(不是收口档), 最后一步 steps_left=1 → 收口
    assert "只剩 1 步" in hints[-1]


def test_paths_are_picked_out_of_a_read_command(adapter, tmp_path):
    """`sed -n '1,260p' app/llm.py` 这种命令要能认出它读了哪个文件。

    认不出就等于没有 already_read, 而 run 7 正是这么把同一个文件读了五遍。
    """
    tool = tmp_path / "tool"
    (tool / "app").mkdir(parents=True)
    (tool / "app" / "llm.py").write_text("x = 1\n", encoding="utf-8")
    (tool / "README.md").write_text("hi\n", encoding="utf-8")

    got = adapter._paths_in_command(
        "cd /work/tools/x && sed -n '1,260p' app/llm.py && cat README.md && ls -la", tool)
    assert got == ["app/llm.py", "README.md"]
    # 不存在的、带通配的、非源码后缀的一律不认 —— 这句提示宁可少一条, 不要认错
    assert adapter._paths_in_command("cat nope.py && grep -rn 'def' app/*.py", tool) == []


def test_repeated_reads_are_visible_in_every_payload(adapter, tmp_path, monkeypatch):
    """读过几次必须**每步都摆在 payload 里**, 而不是只在第一次的快照里 ——
    内容掉出 `_summarize` 的窗口之后, 这是 agent 唯一还能看到的"我读过它"。"""
    tool = tmp_path / "tool"
    tool.mkdir()
    (tool / "llm.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.setattr(adapter, "MAX_STEPS", 4)
    ask = _asker([{"action": "bash", "command": "sed -n '1,50p' llm.py"}] * 4)

    adapter.adapt(run={"item_id": 7, "category": "class1_llm_audit"}, tool_dir=tool,
                  sample=_sample(tmp_path), workdir=tmp_path, ask_fn=ask, freeze=False)

    # 第 1 步还没读过任何东西 → None(不是 {})
    assert ask.calls[0]["already_read"] is None
    assert ask.calls[1]["already_read"] == {"llm.py": 1}
    assert ask.calls[3]["already_read"] == {"llm.py": 3}


# ── 实际服务方台账(L4)────────────────────────────────────────────────────────

def test_serving_summary_is_empty_when_no_model_was_called(adapter):
    adapter.reset_serving()
    # 没调模型 ≠ 用了某个模型: 这里不能返回一个看起来像结论的空壳
    assert adapter.serving_summary() == {"calls": 0}


def test_serving_summary_reports_the_model_that_actually_answered(adapter):
    adapter.reset_serving()
    adapter.record_serving("capability_eval_adapter", {
        "serving": {"upstream_model": "openai/deepseek-v4-flash",
                    "upstream_group": "chat-primary",
                    "upstream_api_base": "https://volc.example/v1",
                    "source": "gateway_header", "attempted_fallbacks": 0},
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
    })
    adapter.record_serving("capability_eval_translate", {
        "serving": {"upstream_model": "openai/deepseek-v4-flash",
                    "upstream_group": "chat-primary",
                    "upstream_api_base": "https://volc.example/v1",
                    "source": "gateway_header", "attempted_fallbacks": 0},
        "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3},
    })

    summary = adapter.serving_summary()

    assert summary["calls"] == 2
    assert summary["models"] == {"openai/deepseek-v4-flash": 2}
    assert summary["groups"] == {"chat-primary": 2}
    assert summary["profiles"] == {"capability_eval_adapter": 1, "capability_eval_translate": 1}
    assert summary["tokens"]["total_tokens"] == 18
    assert summary["unverified"] == 0 and summary["fallback_calls"] == 0
    # 同一个模型 + 全部可核验 + 没降级 ⇒ 这一轮的分数能跟同名模型的另一轮直接比
    assert summary["consistent"] is True


def test_a_fallback_call_is_never_reported_as_consistent(adapter):
    adapter.reset_serving()
    adapter.record_serving("capability_eval_adapter", {
        "serving": {"upstream_model": "openai/deepseek-v4-flash",
                    "upstream_group": "chat-primary",
                    "upstream_api_base": "https://az.gptplus5.com/v1",
                    "source": "gateway_header", "attempted_fallbacks": 1},
    })

    summary = adapter.serving_summary()

    assert summary["fallback_calls"] == 1
    assert summary["consistent"] is False
    # 降级后上游地址变了, 报告里要能看出"这一轮不是主线路跑的"
    assert set(summary["upstream_api_bases"]) == {"https://az.gptplus5.com/v1"}


def test_a_call_without_gateway_headers_is_counted_as_unverified(adapter):
    """老平台/直连上游不会带 `x-litellm-*`。这时真实模型**不可核验**, 只能记 unknown。"""
    adapter.reset_serving()
    adapter.record_serving("capability_eval_adapter", {"parsed": {}, "model": "chat-primary"})

    summary = adapter.serving_summary()

    assert summary["models"] == {"unknown": 1}
    assert summary["unverified"] == 1
    assert summary["consistent"] is False


def test_reset_serving_keeps_runs_apart(adapter):
    adapter.reset_serving()
    adapter.record_serving("capability_eval_adapter", {"serving": {"upstream_model": "a"}})
    adapter.reset_serving()
    adapter.record_serving("capability_eval_adapter", {"serving": {"upstream_model": "b"}})

    assert adapter.serving_summary()["models"] == {"b": 1}
