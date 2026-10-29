"""复现结论回写里的「非 web 收尾」单元测试(2026-10-27, 2026-10-29 改口径)。

背景: item#96253(microsoft/autogen) 复现成功后, 用户问「非 web 项目不是应该回填能力库、
删掉复现结果、且不允许再加复现吗」。查实: 回填与自动入队拦截做了, 但 agent 判非 web 后
复现结论仍留在 payload 里, 行状态停在「复现失败」—— 页面上变成「复现失败 + 非Web」的
自相矛盾条目。

2026-10-29 改口径: 非 web 条目不再把 repro_status 抹空, 而是落**终态** not_supported
(即页面上的「无需复现」), 原因写 payload.repro_skip_reason('non_web' / 'env_unsupported')。
抹空撑不住任何一次结论重算 —— item#51988(worktrunk) 实测: 页面上清理一条旧任务, cleanup 就把
还没清理的成功任务结论写回来, 同一个条目同时显示「已复现」和「非Web」。
"""
from __future__ import annotations

from ai4sec_platform.app.api.capabilities import cleanup_repro, start_repro
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


def test_agent_says_non_web_lands_terminal_not_supported() -> None:
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
    # 终态而不是空: 空 repro_status 会被任何一次结论重算复活(item#51988)
    assert payload["repro_status"] == "not_supported"
    assert payload["repro_skip_reason"] == "non_web"
    # 复现原文要摘: 非 web 没有「复现失败原文」可看, 留着卡片会挂「查看复现」
    assert "repro_result" not in payload
    assert payload["is_web"] is False
    assert payload["web_framework"] == ""
    assert payload["web_reclass"].startswith("repro-corrected-")
    assert status == "已淘汰"


def test_partial_verdict_on_non_web_also_lands_terminal() -> None:
    conn = _db()
    item_id = _mk_item(conn, {"is_web": True, "web_framework": "FastAPI"})
    repro_step._write_payload(
        item_id, "partial", {"verdict": "partial"},
        item_status="部分复现",
        web_report={"is_web": False, "summary": "无 Web 界面"},
    )
    status, payload = _read(conn, item_id)
    assert payload["repro_status"] == "not_supported"
    assert payload["repro_skip_reason"] == "non_web"
    assert "repro_result" not in payload
    assert status == "已淘汰"


def test_docker_required_not_supported_keeps_conclusion() -> None:
    """环境不支持(必须 Docker) 是终态, 不能摘掉结论, 也不能改 web 分类(2026-10-29 修正)。

    item#10711(LingMi1/agent-go) 实测: agent 在 Docker 硬依赖时按旧提示词报了 is_web=false,
    于是一个自带 React 界面的项目被打上「非 Web(不参与复现)」, 页面上自相矛盾。
    is_web 只描述项目本身有没有 Web 界面, 与能不能在本环境跑起来无关。
    """
    conn = _db()
    item_id = _mk_item(conn, {"is_web": True, "web_framework": "React"})
    repro_step._write_payload(
        item_id, "not_supported", {"verdict": "failed"},
        item_status=repro_step._STATUS_TO_ITEM["not_supported"],
        web_report={"is_web": False, "summary": "项目必须 Docker, 本环境不支持 Docker, 按平台规则不复现"},
    )
    status, payload = _read(conn, item_id)
    assert payload["repro_status"] == "not_supported"
    # 原因与 non_web 分开记: 徽标统一写「无需复现」, 抽屉里才能说清是环境边界而不是项目坏了
    assert payload["repro_skip_reason"] == "env_unsupported"
    assert payload["repro_result"] == {"verdict": "failed"}
    assert payload["is_web"] is True
    assert payload["web_framework"] == "React"
    assert "web_reclass" not in payload
    # 行状态用「无需复现」(2026-10-29 更名, 原「无法复现」)
    assert status == "无需复现"


def test_not_supported_does_not_invent_web_classification() -> None:
    """原 payload 没有 is_web 时, not_supported 也不得凭报告凭空写入分类。"""
    conn = _db()
    item_id = _mk_item(conn, {"code_url": "https://github.com/LingMi1/agent-go"})
    repro_step._write_payload(
        item_id, "not_supported", {"verdict": "failed"},
        item_status="无法复现",
        web_report={"is_web": False, "summary": "项目必须 Docker"},
    )
    _, payload = _read(conn, item_id)
    assert "is_web" not in payload
    assert "web_framework" not in payload
    assert "web_reclass" not in payload
    assert payload["repro_skip_reason"] == "env_unsupported"


def test_web_gate_demotion_lands_terminal_not_supported() -> None:
    """分类阶段判死非 web 的收尾也走同一个终态(原先是把 repro_status 抹空)。"""
    from ai4sec_platform.domains.capabilities.assessments import _mark_repro_skipped

    conn = _db()
    item_id = _mk_item(conn, {
        "is_web": False, "web_framework": "SKIP",
        "repro_status": "success", "repro_result": {"verdict": "success"},
    })
    _mark_repro_skipped(conn, item_id, "non_web")
    conn.commit()
    _, payload = _read(conn, item_id)
    assert payload["repro_status"] == "not_supported"
    assert payload["repro_skip_reason"] == "non_web"
    assert "repro_result" not in payload
    # 只动复现维度: 分类字段原样保留
    assert payload["is_web"] is False and payload["web_framework"] == "SKIP"


def test_later_normal_verdict_clears_skip_reason() -> None:
    """原因只跟着终态走: 重跑出正常结论后, 上一轮的「无需复现」原因必须消失。

    本仓的 payload 是浅 merge(永不删键), 所以这条只能靠显式 json_remove 保证 —— 漏了就会
    出现「已复现 + 原因: 依赖 Docker」这种自相矛盾。
    """
    conn = _db()
    item_id = _mk_item(conn, {"is_web": True, "repro_status": "not_supported",
                             "repro_skip_reason": "env_unsupported"})
    repro_step._write_payload(
        item_id, "success", {"verdict": "success"},
        item_status="已复现",
        web_report={"is_web": True, "web_framework": "FastAPI"},
    )
    status, payload = _read(conn, item_id)
    assert payload["repro_status"] == "success"
    assert "repro_skip_reason" not in payload
    assert status == "已复现"


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


def _mk_task(conn, item_id: int, status: str) -> int:
    task_id = repo.create_repro_task(conn, item_id=item_id, repo_url="https://github.com/x/y")
    conn.execute("UPDATE capability_repro_tasks SET status = ? WHERE id = ?", (status, task_id))
    conn.commit()
    return task_id


def test_cleanup_does_not_resurrect_conclusion_on_non_web_item() -> None:
    """清理一条旧任务不得把非 web 条目的复现结论写回来(item#51988 worktrunk 实测)。

    复现判非 web 后条目落终态「无需复现」, 但该 item 名下还留着一条没清理的成功任务。
    用户在页面上清理另一条老任务时, 旧实现先看「剩余任务」分支, 把那条成功任务的结论
    当成该 item 的最新结论写回 payload —— 同一个条目同时显示「已复现」和「非Web」。
    非 web 判断必须排在前面, 且落终态而不是抹空。
    """
    conn = _db()
    item_id = _mk_item(
        conn,
        {"is_web": False, "web_framework": "", "repro_status": "not_supported",
         "repro_skip_reason": "non_web", "repro_result": {"verdict": "success"}},
        status="已淘汰",
    )
    old_task = _mk_task(conn, item_id, "failed")
    _mk_task(conn, item_id, "success")  # 还没清理的旧成功任务 —— 就是它会"复活"结论

    cleanup_repro(old_task, conn=conn)

    status, payload = _read(conn, item_id)
    assert payload["repro_status"] == "not_supported"
    assert payload["repro_skip_reason"] == "non_web"
    assert "repro_result" not in payload
    assert status == "已淘汰"
    assert conn.execute("SELECT status FROM capability_repro_tasks WHERE id = ?", (old_task,)).fetchone()["status"] == "cleaned"


def test_cleanup_still_restores_conclusion_for_web_item() -> None:
    """web 条目不受影响: 清掉一条后结论仍回到剩下的那条任务。"""
    conn = _db()
    item_id = _mk_item(conn, {"is_web": True, "web_framework": "FastAPI"}, status="待复现验证")
    old_task = _mk_task(conn, item_id, "failed")
    _mk_task(conn, item_id, "success")

    cleanup_repro(old_task, conn=conn)

    status, payload = _read(conn, item_id)
    assert payload["repro_status"] == "success"
    assert "repro_skip_reason" not in payload
    assert status == "待复现验证"
