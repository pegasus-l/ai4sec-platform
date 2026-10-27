"""复现结论回写里的「非 web 收尾」单元测试(2026-10-27)。

背景: item#96253(microsoft/autogen) 复现成功后, 用户问「非 web 项目不是应该回填能力库、
删掉复现结果、且不允许再加复现吗」。查实: 回填与自动入队拦截做了, 但 agent 判非 web 后
复现结论仍留在 payload 里, 行状态停在「复现失败」—— 页面上变成「复现失败 + 非Web」的
自相矛盾条目。这里锁住收尾口径, 同时锁住 not_supported(Docker 依赖)不被误伤。
"""
from __future__ import annotations

from ai4sec_platform.app.api.capabilities import start_repro
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.steps import repro as repro_step


def _db():
    conn = connect()
    init_db(conn)
    return conn


def _mk_item(conn, payload=None, status="待复现验证"):
    item_id = repo.create_domain_item(
        conn,
        domain="capabilities",
        item_type="capability",
        title="microsoft/autogen",
        status=status,
        payload=payload if payload is not None else {},
    )
    conn.commit()
    return item_id


def _read(conn, item_id):
    row = repo.get_domain_item(conn, "capabilities", item_id)
    return row["status"], dict(row["payload"] or {})


def test_agent_says_non_web_strips_repro_conclusion_and_recycles_row() -> None:
    conn = _db()
    item_id = _mk_item(conn, {
        "is_web": True,
        "web_framework": "autogenstudio",
        "repro_status": "in_progress",
        "repro_result": {"running": True},
    })
    repro_step._write_payload(
        item_id, "failed", {"verdict": "failed", "summary": "项目没有 Web 界面"},
        item_status="复现失败",
        web_report={"is_web": False, "summary": "纯 CLI 框架, 无 Web 界面", "web_framework": ""},
    )
    status, payload = _read(conn, item_id)
    assert "repro_status" not in payload
    assert "repro_result" not in payload
    assert payload["is_web"] is False
    assert payload["web_framework"] == ""
    assert payload["web_reclass"].startswith("repro-corrected-")
    assert status == "已淘汰"


def test_partial_verdict_on_non_web_also_strips() -> None:
    conn = _db()
    item_id = _mk_item(conn, {"is_web": True, "web_framework": "FastAPI"})
    repro_step._write_payload(
        item_id, "partial", {"verdict": "partial"},
        item_status="部分复现",
        web_report={"is_web": False, "summary": "无 Web 界面"},
    )
    status, payload = _read(conn, item_id)
    assert "repro_status" not in payload and "repro_result" not in payload
    assert status == "已淘汰"


def test_docker_required_not_supported_keeps_conclusion() -> None:
    """环境不支持(必须 Docker) 同样报 is_web=false, 但那是终态, 不能摘掉结论。"""
    conn = _db()
    item_id = _mk_item(conn, {"is_web": True, "web_framework": "FastAPI"})
    repro_step._write_payload(
        item_id, "not_supported", {"verdict": "failed"},
        item_status="无法复现",
        web_report={"is_web": False, "summary": "项目必须 Docker, 本环境不支持 Docker, 按平台规则不复现"},
    )
    status, payload = _read(conn, item_id)
    assert payload["repro_status"] == "not_supported"
    assert payload["repro_result"] == {"verdict": "failed"}
    assert payload["is_web"] is False
    assert status == "无法复现"


def test_web_verdict_keeps_conclusion_as_before() -> None:
    conn = _db()
    item_id = _mk_item(conn, {"is_web": False, "web_framework": ""})
    repro_step._write_payload(
        item_id, "success", {"verdict": "success"},
        item_status="已复现",
        web_report={"is_web": True, "web_framework": "FastAPI + React(Gatsby)", "web_started": True},
    )
    status, payload = _read(conn, item_id)
    assert payload["repro_status"] == "success"
    assert payload["is_web"] is True
    assert payload["web_framework"] == "FastAPI + React(Gatsby)"
    assert status == "已复现"


def test_interrupted_report_without_web_verdict_keeps_conclusion() -> None:
    """中断兜底报告没有 is_web —— 不得据此改分类, 也不得摘结论(这正是 96253 前两次失败的样子)。"""
    conn = _db()
    item_id = _mk_item(conn, {"is_web": True, "web_framework": "autogenstudio"})
    repro_step._write_payload(
        item_id, "failed", {"verdict": "failed", "summary": "复现过程中断"},
        item_status="复现失败",
        web_report={"status": "failed", "summary": "复现过程中断(agent 未输出最终报告)"},
    )
    status, payload = _read(conn, item_id)
    assert payload["repro_status"] == "failed"
    assert payload["is_web"] is True
    assert payload["web_framework"] == "autogenstudio"
    assert "web_reclass" not in payload
    assert status == "复现失败"


def test_start_repro_skips_non_web_item() -> None:
    conn = _db()
    item_id = _mk_item(conn, {
        "is_web": False,
        "web_framework": "",
        "code_url": "https://github.com/microsoft/autogen",
        "repro_status": "failed",
    })
    res = start_repro(item_id, conn=conn)
    assert res["ok"] is True
    assert res["skipped"] is True
    assert res["reason"] == "non_web"
    assert "task_id" not in res
