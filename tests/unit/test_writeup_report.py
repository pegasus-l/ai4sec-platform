"""T4.3:八节复现报告。

报告最容易出的问题不是写不出来, 而是**写得太顺**:

- 模型的位置类断言(文件/函数/摘录代码)没人核对 ⇒ 报告里出现一个不存在的文件, 看起来和真的
  一模一样;
- 模型的归因与平台结论冲突 ⇒ 一条判 `failed`(我们的锅)的任务, 报告里写成"原文没写清";
- 规律没有不变量 ⇒ 第 7 节变成"这篇有个洞"的复述, 却挂着"可复用"的牌子;
- 模型网关挂了 ⇒ 落一份只有 1/2/3/4 节的半截报告, 读者以为 5/6/7 就是空的。

所以下面的用例逐条对着这些"看起来对"的失败方式, 以及"模型报错一行都不写"这条纪律。
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities.writeup_repro import report as report_module
from ai4sec_platform.domains.capabilities.writeup_repro import tasks

ARTICLE = """# acme 路径前缀鉴权绕过

acme 1.2.3 的 auth.py 里, check() 用 startswith 判断前缀:

    if path.startswith('/admin'):
        return allow()

访问 /admin;x 会先被授权层拒绝, 再被路由层放行。
"""

GOOD_MODEL = {
    "attribution": {
        "side": "ours",
        "reason": "沙箱里没有起起 acme 服务, probe 打到的是 404 而不是被拒后的回显",
        "evidence_refs": [1, 2],
    },
    "root_cause": {
        "location": {"file": "auth.py", "function": "check", "lines": ""},
        "invariant": "授权判定用的路径串必须与路由分派用的路径串是同一个",
        "broken_by": "授权层按 /admin 判前缀拒绝, 路由层按 /admin;x 分派到同一 handler",
        "preconditions": ["路由层支持矩阵参数"],
        "code_quote": "if path.startswith('/admin')",
    },
    "pattern": {
        "code_feature": "存在两处独立解析同一 URL 路径、且只有一处做 normalize",
        "audit_entry": "在受保护路径后追加 ;任意, 对比授权层拒绝与路由层到达",
        "discriminator": "框架把矩阵参数定义为路径的一部分, 而安全策略按路径前缀工作",
        "generalization": "framework",
        "provenance": "from_article",
        "evidence_refs": [],
    },
    "caveats": ["第 6 节的位置来自原文, 没有与 acme 的源码核对"],
}


def _evidence(matched: bool | None = False) -> dict:
    return {
        "version": 1,
        "commands": [
            {"cmd": "python3 -m venv .venv", "exit_code": 0, "stdout_sha1": "a" * 40,
             "stdout_tail": "done", "completed": True},
            {"cmd": "curl -s http://127.0.0.1:8080/admin;x", "exit_code": 404, "stdout_sha1": "b" * 40,
             "stdout_tail": "not found", "completed": True},
        ],
        "probe": {
            "spec_cmd": "curl -s http://127.0.0.1:8080/admin;x",
            "success_signal": "stdout 包含 secret",
            "found": True, "cmd": "curl -s http://127.0.0.1:8080/admin;x",
            "exit_code": 404, "shell_exit_code": 404, "exit_code_source": "shell",
            "stdout_sha1": "b" * 40, "stdout_tail": "not found",
            "matched": matched, "checks": [], "why": "", "occurrences": 1,
        },
        "egress": {}, "guard": {"allowed": True},
        "agent_claim": {"self_verdict": "partial"},
        "duration_seconds": 120, "tool_calls": 2,
        "incomplete": True, "incomplete_reasons": ["probe 判据未满足"],
    }


def _task(**over) -> dict:
    task = {
        "id": 1,
        "material_id": 100,
        "status": "partial",
        "verdict": "partial",
        "failure_reason": "probe_not_matched",
        "claim": "acme 1.2.3 的 /admin 可以用矩阵参数绕过鉴权",
        "claim_quote": "访问 /admin;x 会先被授权层拒绝, 再被路由层放行。",
        "target_kind": "oss_repo",
        "target_repo": "github:acme/app",
        "target_version": "1.2.3",
        "spec_json": {
            "claim": "acme 1.2.3 的 /admin 可以用矩阵参数绕过鉴权",
            "target": {"kind": "oss_repo", "repo": "github:acme/app", "ref": "1.2.3"},
            "steps": [{"run": "curl -s http://127.0.0.1:8080/admin;x", "expect": "返回配置"}],
            "probe": {"cmd": "curl -s http://127.0.0.1:8080/admin;x", "success_signal": "stdout 包含 secret"},
            "root_cause": {
                "location": {"file": "auth.py", "function": "check"},
                "invariant": "授权判定用的路径串必须与路由分派用的路径串是同一个",
                "provenance": "llm_extracted", "caveats": [],
            },
        },
    }
    task.update(over)
    return task


def _material() -> dict:
    return {"id": 100, "title": "acme 路径前缀鉴权绕过", "url": "http://blog/1", "cleaned_text": ARTICLE}


def _candidate() -> dict:
    return {
        "claimed_effect": "未授权的用户可读到配置",
        "evidence_quote": "访问 /admin;x 会先被授权层拒绝, 再被路由层放行。",
        "target_cve": "",
        "target_product": "acme",
        "poc_lang": "shell",
        "env_hint": "",
    }


def _build(model: dict | None = GOOD_MODEL, **over) -> dict:
    kwargs = {"task": _task(), "material": _material(), "candidate": _candidate(),
              "evidence": _evidence(), "model_sections": model}
    kwargs.update(over)
    return report_module.build_report(**kwargs)


# ---------------------------------------------------------------- 八节骨架

def test_the_eight_sections_are_filled_and_speakers_never_mix() -> None:
    report = _build()

    assert report["verdict"] == "partial" and report["failure_reason"] == "probe_not_matched"
    assert report["claim_json"]["speaker"] == "author"
    assert report["evidence_json"]["section"]["speaker"] == "platform"
    assert report["evidence_json"]["section"]["command_count"] == 2
    assert report["observed_json"]["speaker"] == "platform"
    assert report["attribution_json"]["speaker"] == "model"
    assert report["root_cause_json"]["speaker"] == "model"
    assert report["pattern_json"]["speaker"] == "model"
    assert report["caveats"], "第 8 节永远不能是空的"
    assert report["generated_by"] == "hybrid"


def test_the_verdict_and_its_reason_are_copied_from_the_task() -> None:
    """模型写什么都改不了第 1 节 —— 结论是判定层算出来的。"""
    model = dict(GOOD_MODEL, attribution={"side": "article", "reason": "原文没写清", "evidence_refs": []})
    report = _build(model, task=_task(verdict="cannot_repro", failure_reason="article_incomplete"))

    assert (report["verdict"], report["failure_reason"]) == ("cannot_repro", "article_incomplete")
    assert report["attribution_json"]["side"] == "article"


def test_the_third_section_never_reads_the_agents_own_report() -> None:
    """agent 的 self_verdict 只作为"当事方陈述"单列, 不能混进执行记录。"""
    report = _build()
    section = report["evidence_json"]["section"]
    assert section["commands"][0]["exit_code"] == 0
    assert report["observed_json"]["agent_self_report"]["self_verdict"] == "partial"


def test_a_three_valued_probe_match_is_preserved() -> None:
    """判不了(None)不能写成没命中(False) —— 那是把"我们没法判"记成"原文没做到"。"""
    report = _build(**{"evidence": _evidence(matched=None)})
    assert report["observed_json"]["matched"] is None


# ---------------------------------------------------------------- 第 5 节: 归因

def test_attribution_can_only_cite_commands_that_exist() -> None:
    model = dict(GOOD_MODEL, attribution={"side": "ours", "reason": "环境没起来", "evidence_refs": [1, 99, "x"]})
    report = _build(model)

    assert report["attribution_json"]["evidence_refs"] == [1]
    assert any("99" in item for item in report["caveats"])


def test_a_conflicting_attribution_loses_to_the_platform_verdict() -> None:
    """平台判 failed(我们的锅), 模型却说是原文的锅 —— 报告不能自相矛盾, 但模型原话要留痕。"""
    model = dict(GOOD_MODEL, attribution={"side": "article", "reason": "原文没写清", "evidence_refs": [1]})
    report = _build(model, task=_task(verdict="failed", failure_reason="env_error"))

    attribution = report["attribution_json"]
    assert attribution["side"] == "ours"
    assert attribution["model_side"] == "article"
    assert any("不符" in item for item in report["caveats"])


def test_success_has_no_attribution_side() -> None:
    report = _build(task=_task(status="success", verdict="success", failure_reason=""))
    attribution = report["attribution_json"]
    assert attribution["side"] == ""
    assert "无需归因" in attribution["reason"]


def test_a_blocked_task_still_gets_an_answer_to_section_five() -> None:
    """一句话都没跑的任务也要归因(客观限制), 不能空着。"""
    empty = {"commands": [], "probe": {"found": False, "matched": None},
             "guard": {"allowed": False, "detail": "目标是在线服务 shop.acme-prod.com"},
             "egress": {}, "incomplete": True, "incomplete_reasons": ["找不到 probe 命令的实际执行记录"]}
    report = _build({"attribution": {}, "root_cause": {}, "pattern": {}, "caveats": []},
                    task=_task(status="blocked", verdict="blocked", failure_reason="online_target"),
                    evidence=empty)

    assert report["attribution_json"]["side"] == "objective"
    assert report["evidence_json"]["section"]["commands"] == []
    assert any("没有采集到任何已执行命令" in item for item in report["caveats"])
    assert report["generated_by"] == "rules"


# ---------------------------------------------------------------- 第 6 节: 根因

def test_a_locatable_root_cause_passes_verification() -> None:
    report = _build()
    root = report["root_cause_json"]
    assert root["provenance"] == "llm_extracted"
    assert report["evidence_json"]["generation"]["root_cause_verified"] is True
    assert any("没有与源码/补丁核对" in item for item in report["caveats"])


def test_a_root_cause_that_points_nowhere_is_downgraded_but_kept() -> None:
    """指错了位置不整份作废: 保留它(可能真指对了), 但标成未核对, 理由进 caveats。"""
    model = dict(GOOD_MODEL, root_cause=dict(
        GOOD_MODEL["root_cause"],
        location={"file": "nope/strategy.py", "function": "apply", "lines": "42"},
    ))
    report = _build(model)

    assert report["root_cause_json"]["provenance"] == "llm_extracted_unverified"
    assert report["evidence_json"]["generation"]["root_cause_verified"] is False
    assert any("strategy.py" in item and "找不到" in item for item in report["caveats"])
    assert report["pattern_json"]["verified"] is False, "第 6 节没过校验, 规律不许入库"


def test_a_missing_root_cause_falls_back_to_the_verified_spec_one() -> None:
    report = _build(dict(GOOD_MODEL, root_cause={}))
    root = report["root_cause_json"]
    assert root["invariant"].startswith("授权判定用的路径串")
    assert report["evidence_json"]["generation"]["root_cause_source"] == "spec"


# ---------------------------------------------------------------- 第 7 节: 规律

def test_a_pattern_without_an_invariant_is_not_a_pattern() -> None:
    """没有不变量的"规律"只是"这篇有个洞"的复述 —— 它不该出现在第 7 节。"""
    model = dict(GOOD_MODEL,
                 root_cause=dict(GOOD_MODEL["root_cause"], invariant=""),
                 pattern=dict(GOOD_MODEL["pattern"], invariant=""))
    report = _build(model)

    assert report["pattern_json"] == {}
    assert report["evidence_json"]["generation"]["pattern_verified"] is False
    assert any("没有不变量" in item for item in report["caveats"])


def test_from_repro_without_evidence_is_downgraded() -> None:
    """`from_repro` 价值最高, 也最容易被编造 —— 对不回命令就不许标。"""
    pattern = dict(GOOD_MODEL["pattern"], provenance="from_repro", evidence_refs=[])
    report = _build(dict(GOOD_MODEL, pattern=pattern))

    assert report["pattern_json"]["provenance"] == "llm_extracted"
    assert any("from_repro" in item for item in report["caveats"])


def test_from_repro_with_a_real_command_reference_survives() -> None:
    pattern = dict(GOOD_MODEL["pattern"], provenance="from_repro", evidence_refs=[2])
    report = _build(dict(GOOD_MODEL, pattern=pattern))

    assert report["pattern_json"]["provenance"] == "from_repro"
    assert report["pattern_json"]["evidence_refs"] == [2]


def test_a_pattern_missing_an_executable_form_is_not_citable() -> None:
    pattern = dict(GOOD_MODEL["pattern"], audit_entry="")
    report = _build(dict(GOOD_MODEL, pattern=pattern))

    assert report["pattern_json"]["verified"] is False
    assert any("审计入口" in item for item in report["caveats"])


def test_an_unknown_generalization_is_not_silently_defaulted() -> None:
    """泛化边界标错了规律就变成噪声 —— 宁可留空, 也不给一个假的 framework。"""
    pattern = dict(GOOD_MODEL["pattern"], generalization="everything")
    report = _build(dict(GOOD_MODEL, pattern=pattern))

    assert report["pattern_json"]["generalization"] == ""
    assert report["pattern_json"]["verified"] is False


def test_llm_extracted_without_confidence_is_flagged() -> None:
    pattern = dict(GOOD_MODEL["pattern"], provenance="llm_extracted", confidence=None)
    report = _build(dict(GOOD_MODEL, pattern=pattern))

    assert any("置信度" in item for item in report["caveats"])


# ---------------------------------------------------------------- 模型失败: 一行不写

_URIS: dict[sqlite3.Connection, str] = {}


def _conn(task_status: str = "partial", verdict: str = "partial") -> sqlite3.Connection:
    # 共享缓存的内存库: 写报告时 ``report._connect()`` 会自己开一条连接, 普通 ``:memory:``
    # 各连各的, 那条连接看不到这里的表。每条用例一个唯一名字, 免得互相串。
    uri = f"file:wrtest_{len(_URIS)}?mode=memory&cache=shared"
    conn = sqlite3.connect(uri, uri=True)
    _URIS[conn] = uri
    conn.row_factory = sqlite3.Row
    init_db(conn)
    conn.execute(
        "INSERT INTO domain_items (id, domain, item_type, title, status, source, source_url,"
        " primary_date, payload_json, created_at, updated_at)"
        " VALUES (100, 'vulnerabilities', 'material', 'acme', 'active', 'src', 'http://blog/1',"
        " '2026-11-01', ?, 'now', 'now')",
        (json.dumps({"cleaned_text": ARTICLE}),),
    )
    conn.execute(
        "INSERT INTO writeup_repro_tasks (id, material_id, status, verdict, failure_reason,"
        " claim, claim_quote, spec_json, evidence_json, created_at, updated_at)"
        " VALUES (1, 100, ?, ?, 'probe_not_matched', 'claim', 'quote', ?, ?, 'x', 'x')",
        (task_status, verdict, json.dumps(_task()["spec_json"]), json.dumps(_evidence())),
    )
    conn.commit()
    return conn


def _reopen(conn: sqlite3.Connection) -> sqlite3.Connection:
    """再开一条指向同一个内存库的连接(模拟写报告模块自己 `_connect()`)。"""
    fresh = sqlite3.connect(_URIS[conn], uri=True)
    fresh.row_factory = sqlite3.Row
    return fresh


def _report_count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM writeup_repro_reports").fetchone()[0])


def _patch_model(monkeypatch, outcome: dict) -> None:
    monkeypatch.setattr(report_module, "generate_model_sections", lambda payload: outcome)


def test_a_model_error_writes_no_report_at_all(monkeypatch) -> None:
    """半份报告会被读成"5/6/7 节就是空的", 而不是"这次没跑成"。"""
    conn = _conn()
    _patch_model(monkeypatch, {"status": "error", "reason": "HTTP 403", "sections": {}})

    result = report_module.write_report_for_task(1, conn=conn)

    assert result["status"] == "error"
    assert _report_count(conn) == 0


def test_no_model_writes_no_report_either(monkeypatch) -> None:
    conn = _conn()
    _patch_model(monkeypatch, {"status": "no_model", "reason": "本地规则模式", "sections": {}})

    assert report_module.write_report_for_task(1, conn=conn)["status"] == "no_model"
    assert _report_count(conn) == 0


def test_a_report_is_written_once_and_regeneration_overwrites_it(monkeypatch) -> None:
    conn = _conn()
    _patch_model(monkeypatch, {"status": "success", "sections": GOOD_MODEL,
                               "provider": "fake", "model": "fake-1"})

    first = report_module.write_report_for_task(1, conn=conn)
    assert first["status"] == "ok" and _report_count(conn) == 1
    assert first["report"]["verdict"] == "partial"
    assert first["report"]["caveats"]

    again = report_module.write_report_for_task(1, conn=conn)
    assert again["status"] == "exists"

    rewritten = report_module.write_report_for_task(1, conn=conn, regenerate=True)
    assert rewritten["status"] == "ok" and _report_count(conn) == 1


def test_an_unfinished_task_gets_no_report(monkeypatch) -> None:
    conn = _conn(task_status="running", verdict="")
    _patch_model(monkeypatch, {"status": "success", "sections": GOOD_MODEL})

    assert report_module.write_report_for_task(1, conn=conn)["status"] == "not_finished"
    assert _report_count(conn) == 0


def test_a_task_without_a_verdict_gets_no_report(monkeypatch) -> None:
    """cancelled / spec_failed 没有结论, 也就没有第 1 节可写。"""
    conn = _conn(task_status="cancelled", verdict="")
    _patch_model(monkeypatch, {"status": "success", "sections": GOOD_MODEL})

    assert report_module.write_report_for_task(1, conn=conn)["status"] == "not_applicable"
    assert _report_count(conn) == 0


# ---------------------------------------------------------------- 库侧约束

def test_the_schema_refuses_an_empty_section_eight() -> None:
    conn = _conn()
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO writeup_repro_reports (task_id, material_id, verdict, caveats,"
            " generated_by, created_at) VALUES (9, 100, 'success', '   ', 'rules', 'x')"
        )


def test_saving_never_leaves_caveats_empty() -> None:
    """DB 的 CHECK 只看"非空白", 所以兜底要写在写入这一层。"""
    conn = _conn()
    saved = report_module.save_report(conn, {
        "task_id": 1, "material_id": 100, "verdict": "success", "failure_reason": "",
        "caveats": [], "generated_by": "rules",
    })
    assert saved["caveats"], "空 caveats 会被替换成兜底说明"
    assert "未包含模型" in saved["caveats"][0]


# ---------------------------------------------------------------- 模型输入

def test_the_prompt_payload_carries_the_verdict_and_the_commands() -> None:
    sections = {
        "claim": report_module.claim_section(_task(), _material(), _candidate()),
        "execution": report_module.execution_section(_evidence()),
        "observed": report_module.observed_section(_evidence(), _candidate()),
    }
    payload = report_module.build_model_payload(_task(), _material(), _candidate(), _evidence(), sections)

    assert payload["verdict"] == "partial"
    assert payload["execution"]["command_count"] == 2
    assert "startswith" in payload["article"]
    assert payload["observed"]["matched"] is False


def test_the_article_is_clipped_for_the_model() -> None:
    material = dict(_material(), cleaned_text="x" * (report_module.ARTICLE_EXCERPT_CHARS + 500))
    sections = {
        "claim": report_module.claim_section(_task(), material, _candidate()),
        "execution": report_module.execution_section(_evidence()),
        "observed": report_module.observed_section(_evidence(), _candidate()),
    }
    payload = report_module.build_model_payload(_task(), material, _candidate(), _evidence(), sections)
    assert len(payload["article"]) < report_module.ARTICLE_EXCERPT_CHARS + 50
    assert payload["article"].endswith("…(已截断)")


# ---------------------------------------------------------------- 端到端: 执行器

def test_finishing_a_task_also_writes_the_report(monkeypatch) -> None:
    """执行器是主要入口: 结论落下之后, 报告要跟着出现(不能等页面来点)。"""
    from ai4sec_platform.domains.capabilities.writeup_repro import executor

    conn = _conn(task_status="running", verdict="")
    monkeypatch.setattr(executor, "_connect", lambda: _reopen(conn))
    monkeypatch.setattr(report_module, "_connect", lambda: _reopen(conn))
    monkeypatch.setattr(executor, "_log", lambda task_id, line: None)
    _patch_model(monkeypatch, {"status": "success", "sections": GOOD_MODEL,
                               "provider": "fake", "model": "fake-1"})

    executor._finish(1, "partial", "probe_not_matched", [], evidence=_evidence())

    assert tasks.get_task(conn, 1)["status"] == "partial"
    assert _report_count(conn) == 1


def test_a_cancelled_task_does_not_trigger_a_report(monkeypatch) -> None:
    from ai4sec_platform.domains.capabilities.writeup_repro import executor

    conn = _conn(task_status="running", verdict="")
    monkeypatch.setattr(executor, "_connect", lambda: _reopen(conn))
    monkeypatch.setattr(executor, "_log", lambda task_id, line: None)
    called: list[int] = []
    monkeypatch.setattr(report_module, "write_report_for_task", lambda *a, **k: called.append(1) or {})

    executor._finish(1, "cancelled", "", [])

    assert tasks.get_task(conn, 1)["status"] == "cancelled"
    assert called == []
