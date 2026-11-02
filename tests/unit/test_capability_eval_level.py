"""能力库 E0 等级单测(domains/capabilities/eval_level.py)。

口径要点(每条断言背后都有一次真实的误判风险):
  - 等级由证据算, **不看报告的 status** —— 报告说 success 也得拿得出来东西;
  - contract 口径严格累积: 低一级没证据, 高一级不成立;
  - 历史报告(没有 build 字段)封顶 L3, 且缺证据的每一级都要写进 caveats;
  - 页面自检 ok 但正文只有十几个字符(SPA 空壳)不能算冒烟通过;
  - 没有证据的一轮(L0)不许覆盖已有证据的结论。
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from ai4sec_platform.domains.capabilities import eval_level as e0


def _report(**over):
    base = {
        "status": "success",
        "build": {"command": "pnpm install && pnpm build", "exit_code": 0, "artifact": "dist/index.html"},
        "web_started": True,
        "start_command": "sh /workspace/.repro-web/task-1.sh",
        "verify": "curl -o /dev/null -w '%{http_code}' http://localhost:8080/task/1/ → 200",
        "page_check": {"ok": True, "visible_chars": 320, "issues": []},
        "tests": {"framework": "vitest", "result": "pass", "totals": {"passed": 6, "failed": 0}},
        "core_workflow": {
            "mode": "real",
            "verified": True,
            "evidence": ["POST /v3/conversation/add 返回 accepted_ids", "日志 Extraction complete: extracted=2"],
        },
    }
    base.update(over)
    return base


# --------------------------------------------------------------------- 定级
def test_full_contract_evidence_reaches_l4():
    result = e0.compute_e0_level(_report())
    assert result["e0_method"] == "contract"
    assert result["e0_level"] == 4
    assert result["e0_label"] == "核心工作流"
    assert result["missing"] == []
    # 每级都要给出凭什么算出来的
    assert [r["level"] for r in result["rungs"]] == [1, 2, 3, 4]
    assert all(r["ok"] is True for r in result["rungs"])


def test_build_failed_caps_at_l0():
    """构建 exit_code 非 0: 后面三级做得再好也不是有效结果(契约口径严格累积)。"""
    result = e0.compute_e0_level(_report(build={"command": "pnpm install", "exit_code": 1}))
    assert result["e0_method"] == "contract"
    assert result["e0_level"] == 0
    assert "构建" in result["missing"]


def test_build_without_exit_code_is_not_passed():
    result = e0.compute_e0_level(_report(build={"command": "pnpm install"}))
    assert result["e0_level"] == 0
    assert any("退出码" in c for c in result["caveats"])


def test_missing_build_field_is_backfill_and_l4_is_not_counted():
    rep = _report()
    rep.pop("build")
    rep["steps"] = [{"cmd": "pnpm install", "ok": True, "note": "安装依赖"}]
    result = e0.compute_e0_level(rep)
    assert result["e0_method"] == "backfill"
    assert result["e0_level"] == 3  # 核心工作流证据齐全也只到 L3
    assert any("不计 L4" in c for c in result["caveats"])
    assert any("关键步骤" in c for c in result["caveats"])


def test_backfill_never_shows_a_level_whose_rung_failed():
    """等级必须是**真的过得了那一级**: 旧报告有核心工作流叙述但没有测试/页面自检时,
    不能因为「L4 有货」就显示成 L3 —— 那会出现「L3 冒烟 ✗」的自相矛盾。"""
    rep = _report(tests=None, page_check=None)
    rep.pop("build")
    rep["steps"] = [{"cmd": "pip install -e .", "ok": True, "note": "安装依赖"}]
    result = e0.compute_e0_level(rep)
    assert result["e0_level"] == 2
    assert "冒烟" in result["missing"]


def test_backfill_without_build_step_keeps_highest_backed_rung():
    """历史报告既没有 build 也没有安装步骤: 不能凭空给 L1, 按实际证据定 L2。"""
    rep = _report(tests=None, page_check=None, core_workflow={"mode": "real", "verified": False, "evidence": []})
    rep.pop("build")
    rep["steps"] = [{"cmd": "git clone https://github.com/a/b", "ok": True, "note": "克隆"}]
    result = e0.compute_e0_level(rep)
    assert result["e0_level"] == 2
    assert result["rungs"][0]["ok"] is None


def test_page_check_failure_blocks_smoke_even_with_passing_tests():
    rep = _report(page_check={"ok": False, "visible_chars": 0, "issues": ["首页打不开: Connection refused"]})
    result = e0.compute_e0_level(rep)
    assert result["rungs"][2]["ok"] is False
    assert result["e0_level"] == 2
    assert "首页打不开" in result["rungs"][2]["detail"]


def test_empty_shell_page_is_not_smoke_passed():
    """SPA 空壳(可见正文 10 字符 + ok=True)不足以证明页面可用 —— 2026-10-31 实际踩到过。"""
    rep = _report(page_check={"ok": True, "visible_chars": 10}, tests=None)
    result = e0.compute_e0_level(rep)
    assert result["rungs"][2]["ok"] is False
    assert any("正文只有 10 字符" in c for c in result["caveats"])


def test_page_check_alone_can_pass_smoke_when_repo_has_no_tests():
    rep = _report(tests={"result": "not_found"}, page_check={"ok": True, "visible_chars": 151})
    result = e0.compute_e0_level(rep)
    assert result["rungs"][2]["ok"] is True
    assert any("没有测试结果" in c for c in result["caveats"])


def test_failing_tests_block_smoke():
    rep = _report(tests={"framework": "pytest", "result": "fail", "totals": {"passed": 3, "failed": 2}}, page_check=None)
    result = e0.compute_e0_level(rep)
    assert result["rungs"][2]["ok"] is False


def test_mock_core_workflow_is_not_l4():
    rep = _report(core_workflow={"mode": "mock", "verified": True,
                                 "evidence": ["用 fixture 跑通了页面流程, 数据是假的"]})
    result = e0.compute_e0_level(rep)
    assert result["e0_level"] == 3
    assert any("mode≠real" in c for c in result["caveats"])


def test_conclusion_only_evidence_is_not_l4():
    rep = _report(core_workflow={"mode": "real", "verified": True, "evidence": ["已成功验证"]})
    result = e0.compute_e0_level(rep)
    assert result["rungs"][3]["ok"] is False
    assert result["e0_level"] == 3


def test_legacy_string_encoded_fields_are_parsed():
    """旧报告把 verified/evidence 写成了字符串(实测 15/17/1014 都是这样), 不能因此判 L4 失败。"""
    rep = _report(core_workflow={
        "mode": "real",
        "verified": "True",
        "evidence": "['MCP stdio initialize 返回 9 个工具', 'ingest 218 文件 -> 4346 节点']",
    })
    result = e0.compute_e0_level(rep)
    assert result["rungs"][3]["ok"] is True
    assert result["e0_level"] == 4


# ------------------------------------------------------------------- 落库
def _db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(
        "CREATE TABLE domain_items (id INTEGER PRIMARY KEY, domain TEXT, status TEXT, payload_json TEXT);"
        "CREATE TABLE capability_repro_tasks (id INTEGER PRIMARY KEY, item_id INTEGER, status TEXT,"
        " report_json TEXT, finished_at TEXT);"
    )
    return conn


def test_record_and_fetch_roundtrip():
    conn = _db()
    e0.ensure_table(conn)
    e0.record_eval_level(conn, item_id=7, task_id=99, report=_report())
    levels = e0.fetch_levels(conn, [7, 8])
    assert levels[7]["e0_level"] == 4
    assert levels[7]["source_task_id"] == 99
    assert 8 not in levels
    evidence = e0.fetch_evidence(conn, 7)
    assert evidence["e0_label"] == "核心工作流"
    assert len(evidence["rungs"]) == 4


def test_l0_does_not_overwrite_a_verified_level():
    """一次超时/环境抖动(报告无证据 → L0)不能把已有的 L3 洗成「未验」。"""
    conn = _db()
    e0.ensure_table(conn)
    e0.record_eval_level(conn, item_id=7, task_id=1, report=_report())
    e0.record_eval_level(conn, item_id=7, task_id=2, report={"status": "failed", "summary": "超时"})
    assert e0.fetch_levels(conn, [7])[7]["e0_level"] == 4


def test_usable_report_lowers_level_when_new_evidence_says_so():
    conn = _db()
    e0.ensure_table(conn)
    e0.record_eval_level(conn, item_id=7, task_id=1, report=_report())
    e0.record_eval_level(conn, item_id=7, task_id=2,
                         report=_report(build={"command": "pnpm install", "exit_code": 2}))
    assert e0.fetch_levels(conn, [7])[7]["e0_level"] == 0


def test_empty_report_writes_nothing():
    conn = _db()
    e0.ensure_table(conn)
    assert e0.record_eval_level(conn, item_id=7, task_id=1, report={}) is None
    assert e0.fetch_levels(conn, [7]) == {}


def test_backfill_picks_latest_usable_task_and_skips_not_supported():
    conn = _db()
    e0.ensure_table(conn)
    conn.execute("INSERT INTO domain_items VALUES (1,'capabilities','已复现','{\"repro_status\":\"success\"}')")
    conn.execute("INSERT INTO domain_items VALUES (2,'capabilities','无需复现','{\"repro_status\":\"not_supported\"}')")
    # 旧任务成功(历史口径), 之后一次僵尸任务 report_json='{}' 不该被选中
    conn.execute("INSERT INTO capability_repro_tasks VALUES (10,1,'success',?,'')", (json.dumps(_report()),))
    conn.execute("INSERT INTO capability_repro_tasks VALUES (11,1,'cleaned','{}','')")
    conn.execute("INSERT INTO capability_repro_tasks VALUES (12,2,'failed',?,'')", (json.dumps(_report()),))
    stats = e0.backfill(conn, dry_run=True)
    assert stats["written"] == 0
    detail = {d["item_id"]: d for d in stats["items_detail"]}
    assert detail[1]["task_id"] == 10
    assert detail[1]["e0_level"] == 4
    assert 2 not in detail  # 无需复现的条目不算 E0

    stats = e0.backfill(conn)
    assert stats["written"] == 1
    assert e0.fetch_levels(conn, [1])[1]["e0_level"] == 4


@pytest.mark.parametrize("report", [None, {}, {"foo": "bar"}])
def test_unusable_reports_return_none(report):
    assert e0.compute_e0_level(report) is None


# --------------------------------------------------------- 证据来源(e0_source)
def test_source_is_platform_when_page_check_carries_the_level():
    """L4 里 L3 是平台自己采的 page_check ⇒ 这条 L4 的证据不是纯 agent 自述。"""
    result = e0.compute_e0_level(_report())
    assert result["e0_source"] == "platform_page"
    assert result["e0_source_label"] == "含平台页面自检"
    assert [r["owner"] for r in result["rungs"]] == ["agent", "agent", "platform", "agent"]


def test_source_is_agent_only_when_smoke_came_from_agent_tests():
    """同为 L3: 靠 agent 报告的测试结果过关, 与靠平台页面自检过关, 等级一样但分量不同。"""
    result = e0.compute_e0_level(_report(page_check={}, core_workflow={}))
    assert result["e0_level"] == 3
    assert result["e0_source"] == "agent_only"
    assert result["rungs"][2]["source"] == "agent 报告的测试结果"


def test_source_ignores_platform_evidence_that_did_not_carry_the_level():
    """page_check 跑挂了, 等级只到 L2 ⇒ 撑起这一级的是 agent 报告, 不能因为「平台采过」就算 platform。"""
    result = e0.compute_e0_level(_report(page_check={"ok": False, "issues": ["502"]}))
    assert result["e0_level"] == 2
    assert result["e0_source"] == "agent_only"


def test_backfill_page_check_also_counts_as_platform():
    """历史口径封顶 L3, 但 L3 照样可以是平台自检撑起来的。"""
    result = e0.compute_e0_level({
        "status": "success", "steps": [{"cmd": "npm install", "ok": True}],
        "web_started": True, "verify": "ok",
        "page_check": {"ok": True, "visible_chars": 500},
    })
    assert result["e0_method"] == "backfill"
    assert result["e0_level"] == 3
    assert result["e0_source"] == "platform_page"


def test_source_is_persisted_and_read_back():
    """列表/详情都要能直接读到来源, 不能只留在 evidence json 里。"""
    conn = _db()
    e0.ensure_table(conn)
    e0.record_eval_level(conn, item_id=7, task_id=1, report=_report())
    assert e0.fetch_levels(conn, [7])[7]["e0_source"] == "platform_page"
    detail = e0.fetch_evidence(conn, 7)
    assert detail["e0_source"] == "platform_page"
    assert detail["e0_source_label"] == "含平台页面自检"
    # 换成一份没有 page_check 的报告, 来源要跟着降下来(不是一次写成平台就永远是平台)
    e0.record_eval_level(conn, item_id=7, task_id=2, report=_report(page_check={}))
    assert e0.fetch_levels(conn, [7])[7]["e0_source"] == "agent_only"


def test_ensure_table_adds_source_column_to_an_existing_table():
    """上线时表已经存在(11-02 建过), CREATE TABLE IF NOT EXISTS 补不了列, 靠 ALTER 追。"""
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE capability_eval_levels (item_id INTEGER PRIMARY KEY,"
        " domain TEXT NOT NULL DEFAULT 'capabilities', e0_level INTEGER NOT NULL DEFAULT 0,"
        " e0_method TEXT NOT NULL DEFAULT '', e0_evidence_json TEXT NOT NULL DEFAULT '{}',"
        " e0_verified_at TEXT NOT NULL DEFAULT '', source_task_id INTEGER, computed_at TEXT NOT NULL)"
    )
    e0.ensure_table(conn)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(capability_eval_levels)")]
    assert "e0_source" in cols
    e0.ensure_table(conn)  # 幂等: 第二遍不能让 duplicate column 冒出来
