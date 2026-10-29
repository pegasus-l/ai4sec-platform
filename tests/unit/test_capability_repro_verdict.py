"""复现页要跟着能力条目的终态结论走(2026-10-29)。

用户实测: 能力库把 item#50500(kaim56) / #10711(agent-go) 改成「无需复现」后, 复现验证页
仍按任务行的原始结果写「复现失败」; item#51988(worktrunk) 反过来还写着「复现成功」。
同一件事两页两种说法 —— 结论在能力条目(payload.repro_status), 任务行只是执行记录。

这里锁住三件事:
  · 列表与单条详情都把条目结论带出来(前端据此覆盖展示, 不改任务行的真实状态)
  · 结论是「无需复现」以外的值时原样带出(前端不覆盖, 页面显示的还是任务真实状态)
  · 条目行不在了也不能 500(历史任务指向已删除条目)
"""
from __future__ import annotations

from ai4sec_platform.app.api.capabilities import _item_repro_verdicts, get_repro_task, repro_runs
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect


def _db():
    conn = connect()
    init_db(conn)
    return conn


def _mk_item(conn, payload: dict, status: str = "无需复现") -> int:
    item_id = repo.create_domain_item(
        conn,
        domain="capabilities",
        item_type="capability",
        title="LingMi1/agent-go",
        status=status,
        payload=payload,
    )
    conn.commit()
    return item_id


def _mk_task(conn, item_id: int, status: str = "failed") -> int:
    task_id = repo.create_repro_task(conn, item_id=item_id, repo_url="https://github.com/LingMi1/agent-go")
    conn.execute("UPDATE capability_repro_tasks SET status = ? WHERE id = ?", (status, task_id))
    conn.commit()
    return task_id


def test_repro_runs_carry_item_terminal_verdict() -> None:
    """条目落「无需复现」后, 它那条 failed 任务也要带出结论与原因, 否则复现页仍写「复现失败」。"""
    conn = _db()
    item_id = _mk_item(conn, {"repro_status": "not_supported", "repro_skip_reason": "env_unsupported"})
    task_id = _mk_task(conn, item_id, "failed")

    items = {item["id"]: item for item in repro_runs(conn)["items"]}

    assert items[task_id]["status"] == "failed", "任务行仍是执行记录, 不该被改写"
    assert items[task_id]["item_repro_status"] == "not_supported"
    assert items[task_id]["item_repro_skip_reason"] == "env_unsupported"


def test_repro_runs_leave_normal_items_alone() -> None:
    """反向护栏: 正常条目原样带出 candidate, 前端只在 not_supported 时才覆盖展示。"""
    conn = _db()
    item_id = _mk_item(conn, {"repro_status": "candidate"}, status="待复现验证")
    task_id = _mk_task(conn, item_id, "running")

    items = {item["id"]: item for item in repro_runs(conn)["items"]}

    assert items[task_id]["item_repro_status"] == "candidate"
    assert items[task_id]["status"] == "running"


def test_single_task_endpoint_matches_list() -> None:
    """控制台头部读的是 /repro/{id}: 两个端点口径不一致的话, 列表写「无需复现」、点开又写「复现失败」。"""
    conn = _db()
    item_id = _mk_item(conn, {"repro_status": "not_supported", "repro_skip_reason": "non_web"})
    task_id = _mk_task(conn, item_id, "success")

    listed = {item["id"]: item for item in repro_runs(conn)["items"]}[task_id]
    detail = get_repro_task(task_id, conn)

    assert detail["item_repro_status"] == listed["item_repro_status"] == "not_supported"
    assert detail["item_repro_skip_reason"] == listed["item_repro_skip_reason"] == "non_web"


def test_unknown_item_gives_empty_verdict_instead_of_raising() -> None:
    """查不到条目(历史任务指向已删条目)时只许返回空结论 —— 复现页不该因为一条脏数据整页 500。"""
    conn = _db()

    assert _item_repro_verdicts(conn, [999999, None, 0]) == {}
