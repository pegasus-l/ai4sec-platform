"""能力洞察 API - 完整 REST + SSE 端点。

11 个 REST 端点（对齐 demo 4 份数据契约 + 旧 v1 API）:
  GET  /today                          ← demo today.json
  GET  /items                           ← demo library.json
  GET  /items/{id}                      ← demo capability_detail.sample.json
  GET  /repro-runs                      ← demo repro_runs.json
  GET  /conversions                     ← demo conversions.json
  POST /items/{id}/start-repro          ← 旧 /api/repro/start
  POST /repro/{task_id}/stop           ← 旧 /api/repro/{task_id}/stop
  POST /repro/{task_id}/cleanup        ← 旧 /api/repro/{task_id}/cleanup
  POST /items/{id}/mark-conversion     ← 旧 旧无（新增）
  POST /classify/batch                  ← 旧 /api/classify/batch
  GET  /classify/stats                  ← 旧 /api/classify/stats

1 个 SSE 端点（决策 4: SSE 替代 WebSocket）:
  GET  /repro/{task_id}/logs/stream     ← 实时日志流（7 类上色）
"""
from __future__ import annotations

import asyncio
import json
import socket
import sqlite3
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.adapters.repro_runner import classify_log_line, manager as repro_manager
from ai4sec_platform.domains.capabilities.assessments import classify_batch
from ai4sec_platform.domains.capabilities.schemas import ReproTaskResponse
from ai4sec_platform.domains.capabilities.selectors import pick_top_repro_candidates, _resolve_repo_url
from ai4sec_platform.services import domain_items, operations

router = APIRouter(prefix="/capabilities", tags=["capabilities"])
DOMAIN = "capabilities"


# ============================================================================
# 已有端点（保留）
# ============================================================================
@router.get("/today")
def today(limit: int = Query(200, ge=1, le=500), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.today(conn, DOMAIN, limit=limit)


@router.get("/items")
def items(limit: int = Query(200, ge=1, le=500), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, limit=limit)


@router.get("/items/{item_id}")
def item_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="capability item not found")
    return item


@router.get("/repro-runs")
def repro_runs(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """复现任务列表，返回可直接用于详情、操作和 SSE 的真实 task id。"""
    tasks = repo.list_repro_tasks(conn)
    items = []
    for task in tasks:
        task_data = ReproTaskResponse.from_row(task).model_dump()
        task_data.update({
            "task_id": task["id"],
            "display_id": f"repro-{task['item_id']}",
            "capability_id": str(task["item_id"]),
            "title": task.get("repo_url", "").split("/")[-1] if task.get("repo_url") else "",
            "environment": "auto-runner",
            "last_event": task.get("result", "")[:100] if task.get("result") else "",
            "artifacts": [],
        })
        items.append(task_data)
    return {
        "domain": DOMAIN,
        "items": items,
    }


@router.get("/conversion-queue")
def conversion_queue(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.human_queue(conn, DOMAIN)


@router.get("/conversions")
def conversions(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """能力转化记录（对齐 demo conversions.json）"""
    items = repo.list_domain_items(conn, DOMAIN, item_type="capability_conversion", limit=50)
    return {
        "domain": DOMAIN,
        "items": [
            {
                "id": f"conv-{it['id']}",
                "capability_id": str((it.get("payload") or {}).get("capability_id", "")),
                "title": it.get("title", ""),
                "status": (it.get("payload") or {}).get("status", "持续观察"),
                "scenario": (it.get("payload") or {}).get("scenario", ""),
                "owner": (it.get("payload") or {}).get("owner", ""),
                "next_action": (it.get("payload") or {}).get("next_action", ""),
                "notes": (it.get("payload") or {}).get("notes", ""),
            }
            for it in items
        ],
    }


# ============================================================================
# 新增：复现任务端点
# ============================================================================
class StartReproRequest(BaseModel):
    web: bool = False


@router.post("/items/{item_id}/start-repro")
def start_repro(item_id: int, body: StartReproRequest = StartReproRequest(), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """启动复现任务（迁自旧 /api/repro/start）"""
    item = repo.get_domain_item(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="capability item not found")

    demo_url = str((item.get("payload") or {}).get("demo_url") or "").strip()
    if demo_url:
        return {
            "ok": True,
            "skipped": True,
            "reason": "official_demo",
            "item_id": item_id,
            "demo_url": demo_url,
        }

    repo_url = _resolve_repo_url(item)
    if not repo_url:
        raise HTTPException(status_code=400, detail="no repo URL found in item")

    # 清理旧的非成功 task；partial 重试前也要释放容器和端口
    for old_task in repo.list_repro_tasks(conn, item_id=item_id, include_cleaned=True):
        if old_task["status"] in ("partial", "failed", "timeout", "stopped"):
            repro_manager.cleanup_task(
                old_task["id"],
                container_name=old_task.get("container_name"),
                workspace_path=old_task.get("workspace_path"),
                web_port=old_task.get("web_port"),
            )
            repo.update_repro_task(conn, task_id=old_task["id"], status="cleaned", cleaned_at=datetime.utcnow().isoformat())

    # 创建 task
    task_id = repo.create_repro_task(conn, item_id=item_id, repo_url=repo_url, trigger="manual")

    # Web 端口分配
    web_port = None
    if body.web or (item.get("payload") or {}).get("is_web"):
        web_port = _alloc_web_port(conn)
        if web_port:
            repo.update_repro_task(conn, task_id=task_id, web_port=web_port)

    conn.commit()

    # 回调
    def on_log(line: str):
        from ai4sec_platform.db.session import connect as db_connect

        callback_conn = db_connect()
        try:
            repo.append_repro_log(callback_conn, task_id=task_id, line=line)
            callback_conn.commit()
        finally:
            callback_conn.close()

    def on_status(status: str, _tid=task_id, _iid=item_id, **kw):
        from ai4sec_platform.db.session import connect as db_connect

        callback_conn = db_connect()
        update_fields: dict[str, Any] = {"status": status}
        if "result" in kw:
            update_fields["result"] = str(kw["result"])[:10000]
        if status in ("success", "failed", "timeout", "stopped", "partial"):
            update_fields["finished_at"] = datetime.utcnow().isoformat()
        if "report" in kw and kw["report"]:
            update_fields["report_json"] = json.dumps(kw["report"], ensure_ascii=False) if isinstance(kw["report"], dict) else str(kw["report"])
        if "web_port" in kw:
            update_fields["web_port"] = kw["web_port"]
        try:
            repo.update_repro_task(callback_conn, task_id=_tid, **update_fields)
            if "report" in kw and kw["report"]:
                from ai4sec_platform.domains.capabilities.adapters.repro_results import update_capability_from_report
                update_capability_from_report(callback_conn, item_id=_iid, report=kw["report"])
            callback_conn.commit()
        finally:
            callback_conn.close()

    # 启动 ReproRunner
    runner = repro_manager.start_task(
        task_id=task_id,
        repo_url=repo_url,
        on_log=on_log,
        on_status=on_status,
        web_port=web_port,
    )
    repo.update_repro_task(
        conn,
        task_id=task_id,
        container_name=runner.container_name,
        workspace_path=str(runner.workspace),
        web_url=f"http://127.0.0.1:{web_port}" if web_port else "",
    )
    conn.commit()

    return {"ok": True, "task_id": task_id, "repo_url": repo_url, "web_port": web_port}


@router.get("/repro/{task_id}")
def get_repro_task(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """单个复现任务详情"""
    task = repo.get_repro_task(conn, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="repro task not found")
    return ReproTaskResponse.from_row(task).model_dump()


@router.post("/repro/{task_id}/stop")
def stop_repro(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """停止复现任务"""
    task = repo.get_repro_task(conn, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="repro task not found")
    repro_manager.stop_task(task_id)
    repo.update_repro_task(conn, task_id=task_id, status="stopped", finished_at=datetime.utcnow().isoformat())
    conn.commit()
    return {"ok": True}


@router.post("/repro/{task_id}/cleanup")
def cleanup_repro(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """清理复现任务（删容器 + 产物）"""
    task = repo.get_repro_task(conn, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="repro task not found")
    repro_manager.cleanup_task(
        task_id,
        container_name=task.get("container_name"),
        workspace_path=task.get("workspace_path"),
        web_port=task.get("web_port"),
    )
    repo.update_repro_task(
        conn,
        task_id=task_id,
        status="cleaned",
        cleaned_at=datetime.utcnow().isoformat(),
        web_url="",
    )
    conn.commit()
    return {"ok": True}


# ============================================================================
# SSE 实时日志流端点（决策 4: SSE 替代 WebSocket）
# ============================================================================
@router.get("/repro/{task_id}/logs/stream")
async def stream_repro_logs(task_id: int, request: Request, conn: sqlite3.Connection = Depends(get_db)):
    """SSE 实时日志流。事件类型: log/status/end。每行带 kind（7 类上色）。

    SSE 格式:
      event: log\\ndata: {"line": "...", "kind": "tool|read|exec|ok|warn|error|text"}\\n\\n
      event: status\\ndata: {"status": "...", "report": {...}}\\n\\n
      event: end\\ndata: {}\\n\\n

    生产注意: nginx 需 proxy_buffering off + proxy_read_timeout 3600s + 不 gzip。
    """
    task = repo.get_repro_task(conn, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="repro task not found")

    async def event_generator():
        last_len = 0
        while not await request.is_disconnected():
            # 重新查 task（因为 conn 可能被其他线程修改，这里每次新建查询）
            # 注意: Depends(get_db) 的 conn 在 async 生成器里可能已关闭，
            #       改为直接用 session.connect 新建连接
            from ai4sec_platform.db.session import connect as db_connect
            local_conn = db_connect()
            try:
                row = local_conn.execute("SELECT * FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
            finally:
                local_conn.close()

            if not row:
                yield f"event: end\ndata: {{}}\n\n"
                return

            task_dict = dict(row)
            log = task_dict.get("log") or ""
            new_lines = log[last_len:].splitlines()
            last_len = len(log)

            for line in new_lines:
                kind = classify_log_line(line)
                data = json.dumps({"line": line, "kind": kind}, ensure_ascii=False)
                yield f"event: log\ndata: {data}\n\n"

            status = task_dict.get("status", "queued")
            if status in ("success", "partial", "failed", "timeout", "stopped", "cleaned"):
                report_json = task_dict.get("report_json") or "{}"
                report_data = json.loads(report_json) if report_json and report_json != "{}" else None
                status_data = json.dumps({"status": status, "report": report_data}, ensure_ascii=False)
                yield f"event: status\ndata: {status_data}\n\n"
                yield f"event: end\ndata: {{}}\n\n"
                return

            # heartbeat（防 proxy idle timeout）
            yield f": ping\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # nginx 不缓冲
        },
    )


# ============================================================================
# 能力转化端点
# ============================================================================
class MarkConversionRequest(BaseModel):
    status: str = "持续观察"  # 持续观察|已转化|已放弃
    scenario: str = ""
    owner: str = ""
    next_action: str = ""
    notes: str = ""


@router.post("/items/{item_id}/mark-conversion")
def mark_conversion(item_id: int, body: MarkConversionRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """标记能力转化（新增端点）"""
    item = repo.get_domain_item(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="capability item not found")

    # 创建转化记录
    conv_id = repo.create_domain_item(
        conn,
        domain=DOMAIN,
        item_type="capability_conversion",
        title=item.get("title", "未命名能力"),
        summary=body.scenario,
        source="manual",
        tags=["能力转化", body.status],
        metrics={"capability_id": item_id},
        payload={
            "capability_id": item_id,
            "status": body.status,
            "scenario": body.scenario,
            "owner": body.owner,
            "next_action": body.next_action,
            "notes": body.notes,
        },
    )

    # 更新原能力卡的 conversion_status
    repo.update_domain_item(conn, item_id=item_id, payload={"conversion_status": body.status})

    return {"ok": True, "conversion_id": conv_id, "status": body.status}


# ============================================================================
# Web 分类端点（迁自旧 /api/classify/*）
# ============================================================================
@router.post("/classify/batch")
def classify_batch_endpoint(limit: int = 50, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """批量 Web 分类（迁自旧 /api/classify/batch）"""
    # 选未分类的 item
    items = repo.list_domain_items(conn, DOMAIN, item_type="capability", limit=limit * 3)
    candidates = [
        it for it in items
        if not (it.get("payload") or {}).get("web_classify_ts")
        and (
            (it.get("payload") or {}).get("code_url")
            or "github.com" in (it.get("source_url") or "")
        )
    ][:limit]

    if not candidates:
        return {"ok": True, "classified": 0, "failed": 0, "reason": "no unclassified items"}

    result = classify_batch(conn, candidates, limit=limit)
    return {"ok": True, **result}


@router.get("/classify/stats")
def classify_stats(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """Web 分类统计（迁自旧 /api/classify/stats）"""
    items = repo.list_domain_items(conn, DOMAIN, item_type="capability", limit=10000, exclude_status="已淘汰")
    all_items = items
    repo_filter = [
        it for it in all_items
        if (it.get("payload") or {}).get("code_url") or "github.com" in (it.get("source_url") or "")
    ]
    classified = [
        it for it in repo_filter
        if (it.get("payload") or {}).get("web_classify_ts")
    ]
    web_count = sum(1 for it in repo_filter if (it.get("payload") or {}).get("is_web"))
    return {
        "total": len(repo_filter),
        "classified": len(classified),
        "unclassified": len(repo_filter) - len(classified),
        "web_count": web_count,
    }


# ============================================================================
# 辅助函数
# ============================================================================
def _alloc_web_port(conn) -> int | None:
    """分配 Web 端口（18000-18999，跳过已用）"""
    import os
    base = int(os.environ.get("REPRO_WEB_PORT_BASE", "18000"))
    max_port = int(os.environ.get("REPRO_WEB_PORT_MAX", "18999"))
    rows = conn.execute(
        "SELECT DISTINCT web_port FROM capability_repro_tasks WHERE web_port IS NOT NULL AND status IN ('queued', 'running')"
    ).fetchall()
    used = {row["web_port"] for row in rows}
    for port in range(base, max_port + 1):
        if port not in used and _port_is_available(port):
            return port
    return None


def _port_is_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("0.0.0.0", port))
        except OSError:
            return False
    return True


# ============================================================================
# 运营端点（ops）
# ============================================================================
@router.get("/ops/overview")
def ops_overview(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """运营概览：KPI + 审计摘要"""
    from ai4sec_platform.domains.capabilities.service import stats as cap_stats, classify_stats
    from ai4sec_platform.domains.capabilities.audits import audit_repro_failures, audit_missing_fields
    return {
        "stats": cap_stats(conn),
        "classify_stats": classify_stats(conn),
        "repro_failures": audit_repro_failures(conn),
        "missing_fields": audit_missing_fields(conn),
    }


@router.get("/ops/repro-failures")
def ops_repro_failures(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """复现失败审计"""
    from ai4sec_platform.domains.capabilities.audits import audit_repro_failures
    return audit_repro_failures(conn)


@router.get("/ops/missing-fields")
def ops_missing_fields(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """能力卡缺字段审计"""
    from ai4sec_platform.domains.capabilities.audits import audit_missing_fields
    return audit_missing_fields(conn)
