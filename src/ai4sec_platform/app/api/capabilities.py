"""能力洞察 API - 完整 REST + SSE 端点。

11 个 REST 端点（对齐 demo 4 份数据契约 + 旧 v1 API）:
  GET  /today                          ← demo today.json
  GET  /items                           ← demo library.json
  GET  /items/{id}                      ← demo capability_detail.sample.json
  GET  /repro-runs                      ← 正式复现任务列表
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
import sqlite3
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.adapters.repro_runner import classify_log_line, repro_resource_limits_payload
from ai4sec_platform.domains.capabilities.assessments import classify_batch
from ai4sec_platform.domains.capabilities.audits import audit_missing_fields, audit_repro_failures
from ai4sec_platform.domains.capabilities.egress_approvals import (
    ReproEgressApprovalError,
    create_egress_requests,
    list_egress_requests,
    normalize_requested_domains,
    review_egress_request,
)
from ai4sec_platform.domains.capabilities.repro_jobs import request_repro_cleanup, request_repro_stop
from ai4sec_platform.domains.capabilities.repro_policy import (
    ReproQuotaExceededError,
    enqueue_repro_task,
    repro_limits_payload,
    repro_worker_status_payload,
)
from ai4sec_platform.domains.capabilities.repro_ports import allocate_repro_web_port
from ai4sec_platform.domains.capabilities.repro_profiles import (
    ReproProfileApprovalError,
    normalize_execution_profile,
    repro_profile_payload,
    review_nested_docker_profile,
)
from ai4sec_platform.domains.capabilities.repro_strategy import resolve_repro_strategy
from ai4sec_platform.domains.capabilities.schemas import ReproTaskResponse
from ai4sec_platform.domains.capabilities.selectors import pick_top_repro_candidates, _resolve_repo_url
from ai4sec_platform.domains.capabilities.service import classify_stats as capability_classify_stats
from ai4sec_platform.domains.capabilities.service import stats as capability_stats
from ai4sec_platform.services import domain_items, operations

router = APIRouter(prefix="/capabilities", tags=["capabilities"])
DOMAIN = "capabilities"


def _alloc_web_port(conn: sqlite3.Connection) -> int | None:
    return allocate_repro_web_port(conn)


# ============================================================================
# 已有端点（保留）
# ============================================================================
@router.get("/today")
def today(limit: int = Query(12, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.today(conn, DOMAIN, limit=limit)


@router.get("/items")
def items(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, limit=limit)


@router.get("/items/{item_id}")
def item_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="capability item not found")
    return item


@router.get("/repro-runs")
def repro_runs(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """复现任务列表，使用与单任务详情相同的正式契约。"""
    tasks = repo.list_repro_tasks(conn)
    return {
        "domain": DOMAIN,
        "items": [ReproTaskResponse.from_row(task, log_tail_lines=20).model_dump() for task in tasks],
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
    model_config = ConfigDict(extra="forbid")

    strategy: Literal["auto", "local_web", "cli"] = "auto"
    repo_commit: str = Field(default="", pattern=r"^(?:[0-9a-fA-F]{40})?$")
    execution_profile: str = Field(default="standard", max_length=30)
    external_domains: list[str] = Field(default_factory=list, max_length=20)
    egress_purpose: str = Field(default="", max_length=500)
    requested_by: str = Field(default="operator", max_length=100)


class ReproEgressReviewRequest(BaseModel):
    reviewer: str = Field(default="operator", max_length=100)
    reason: str = Field(default="", max_length=500)


class ReproProfileReviewRequest(BaseModel):
    reviewer: str = Field(default="operator", max_length=100)
    reason: str = Field(default="", max_length=1000)


@router.post("/items/{item_id}/start-repro")
def start_repro(item_id: int, body: StartReproRequest = StartReproRequest(), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """创建持久复现任务，由独立 Repro Worker 异步执行。"""
    item = repo.get_domain_item(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="capability item not found")

    decision = resolve_repro_strategy(item, body.strategy)
    if not decision.should_enqueue:
        return {
            "ok": True,
            "skipped": True,
            "reason": decision.strategy,
            "strategy": decision.strategy,
            "message": decision.reason,
            "item_id": item_id,
            "demo_url": decision.demo_url,
        }
    repo_url = _resolve_repo_url(item)
    if not repo_url:
        raise HTTPException(status_code=400, detail="no repo URL found in item")
    web_port = _alloc_web_port(conn) if decision.strategy == "local_web" else None
    if decision.strategy == "local_web" and web_port is None:
        raise HTTPException(status_code=503, detail={"code": "web_port_unavailable", "message": "no loopback Web port is available"})

    try:
        execution_profile = normalize_execution_profile(body.execution_profile)
        external_domains = normalize_requested_domains(body.external_domains)
        initial_status = (
            "awaiting_profile_approval"
            if execution_profile == "nested_docker"
            else "awaiting_egress_approval"
            if external_domains
            else "queued"
        )
        task_id = enqueue_repro_task(
            conn,
            item_id=item_id,
            repo_url=repo_url,
            repo_commit=body.repo_commit.casefold(),
            trigger="manual",
            initial_status=initial_status,
            execution_profile=execution_profile,
            repro_strategy=decision.strategy,
        )
        egress_requests = create_egress_requests(
            conn,
            task_id=task_id,
            domains=external_domains,
            purpose=body.egress_purpose,
            requested_by=body.requested_by,
        )
    except ReproQuotaExceededError as exc:
        status_code = 409 if exc.code == "item_active" else 429
        raise HTTPException(status_code=status_code, detail={"code": exc.code, "message": str(exc)}) from exc
    except ReproEgressApprovalError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": str(exc)}) from exc
    except ReproProfileApprovalError as exc:
        raise HTTPException(status_code=422, detail={"code": exc.code, "message": str(exc)}) from exc

    # 旧失败任务交给 Worker 异步清理，API 不直接操作 Docker 或工作目录。
    for old_task in repo.list_repro_tasks(conn, item_id=item_id, include_cleaned=True):
        if old_task["status"] in ("failed", "timeout", "stopped"):
            request_repro_cleanup(conn, int(old_task["id"]))

    if web_port is not None:
        repo.update_repro_task(conn, task_id=task_id, web_port=web_port)

    return {
        "ok": True,
        "task_id": task_id,
        "repo_url": repo_url,
        "repo_commit": body.repo_commit.casefold(),
        "web_port": web_port,
        "status": initial_status,
        "execution_profile": execution_profile,
        "strategy": decision.strategy,
        "egress_requests": egress_requests,
    }


@router.get("/repro-limits")
def repro_limits(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    payload = repro_limits_payload(conn)
    payload["resources"] = repro_resource_limits_payload()
    return payload


@router.get("/repro-worker-status")
def repro_worker_status(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return repro_worker_status_payload(conn)


@router.get("/repro/{task_id}")
def get_repro_task(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """单个复现任务详情"""
    task = repo.get_repro_task(conn, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="repro task not found")
    return ReproTaskResponse.from_row(task).model_dump()


@router.get("/repro/{task_id}/egress")
def get_repro_egress_requests(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    if not repo.get_repro_task(conn, task_id):
        raise HTTPException(status_code=404, detail="repro task not found")
    return {"task_id": task_id, "items": list_egress_requests(conn, task_id=task_id)}


@router.get("/repro/{task_id}/profile")
def get_repro_profile(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    payload = repro_profile_payload(conn, task_id=task_id)
    if not payload:
        raise HTTPException(status_code=404, detail="repro task not found")
    return payload


def _review_repro_profile(
    *,
    task_id: int,
    decision: str,
    body: ReproProfileReviewRequest,
    conn: sqlite3.Connection,
) -> dict:
    try:
        profile = review_nested_docker_profile(
            conn,
            task_id=task_id,
            decision=decision,
            reviewed_by=body.reviewer,
            reason=body.reason,
        )
    except ReproProfileApprovalError as exc:
        status_code = 404 if exc.code == "task_not_found" else 409 if exc.code in {"already_reviewed", "state_conflict"} else 422
        raise HTTPException(status_code=status_code, detail={"code": exc.code, "message": str(exc)}) from exc
    return {"ok": True, "profile": profile}


@router.post("/repro/{task_id}/profile/approve")
def approve_repro_profile(
    task_id: int,
    body: ReproProfileReviewRequest,
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    return _review_repro_profile(task_id=task_id, decision="approved", body=body, conn=conn)


@router.post("/repro/{task_id}/profile/reject")
def reject_repro_profile(
    task_id: int,
    body: ReproProfileReviewRequest = ReproProfileReviewRequest(),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    return _review_repro_profile(task_id=task_id, decision="rejected", body=body, conn=conn)


def _review_repro_egress(
    *,
    task_id: int,
    request_id: int,
    decision: str,
    body: ReproEgressReviewRequest,
    conn: sqlite3.Connection,
) -> dict:
    try:
        request = review_egress_request(
            conn,
            task_id=task_id,
            request_id=request_id,
            decision=decision,
            reviewed_by=body.reviewer,
            reason=body.reason,
        )
    except ReproEgressApprovalError as exc:
        status_code = 404 if exc.code in {"task_not_found", "request_not_found"} else 409 if exc.code in {"already_reviewed", "state_conflict"} else 422
        raise HTTPException(status_code=status_code, detail={"code": exc.code, "message": str(exc)}) from exc
    task = repo.get_repro_task(conn, task_id)
    return {"ok": True, "task_status": task["status"], "request": request}


@router.post("/repro/{task_id}/egress/{request_id}/approve")
def approve_repro_egress(
    task_id: int,
    request_id: int,
    body: ReproEgressReviewRequest = ReproEgressReviewRequest(),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    return _review_repro_egress(
        task_id=task_id,
        request_id=request_id,
        decision="approved",
        body=body,
        conn=conn,
    )


@router.post("/repro/{task_id}/egress/{request_id}/reject")
def reject_repro_egress(
    task_id: int,
    request_id: int,
    body: ReproEgressReviewRequest = ReproEgressReviewRequest(),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    return _review_repro_egress(
        task_id=task_id,
        request_id=request_id,
        decision="rejected",
        body=body,
        conn=conn,
    )


@router.post("/repro/{task_id}/stop")
def stop_repro(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """持久化停止请求；运行中任务由 Repro Worker 终止。"""
    status = request_repro_stop(conn, task_id)
    if status is None:
        raise HTTPException(status_code=404, detail="repro task not found")
    return {"ok": True, "status": status}


@router.post("/repro/{task_id}/cleanup")
def cleanup_repro(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """持久化清理请求；由 Repro Worker 删除容器和工作目录。"""
    status = request_repro_cleanup(conn, task_id)
    if status is None:
        raise HTTPException(status_code=404, detail="repro task not found")
    return {"ok": True, "status": status}


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
    database_row = conn.execute("PRAGMA database_list").fetchone()
    database_path = str(database_row["file"])

    async def event_generator():
        last_len = 0
        while not await request.is_disconnected():
            # 重新查 task（因为 conn 可能被其他线程修改，这里每次新建查询）
            # 注意: Depends(get_db) 的 conn 在 async 生成器里可能已关闭，
            #       改为直接用 session.connect 新建连接
            local_conn = sqlite3.connect(database_path, timeout=5, check_same_thread=False)
            local_conn.row_factory = sqlite3.Row
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
                try:
                    report_data = json.loads(report_json) if report_json and report_json != "{}" else None
                except (TypeError, json.JSONDecodeError):
                    report_data = None
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
    items = repo.list_domain_items(conn, DOMAIN, item_type="capability", limit=10000)
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


@router.get("/stats")
def stats(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return capability_stats(conn)


@router.get("/ops/overview")
def ops_overview(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return {
        "stats": capability_stats(conn),
        "classify_stats": capability_classify_stats(conn),
        "repro_failures": audit_repro_failures(conn),
        "missing_fields": audit_missing_fields(conn),
    }


@router.get("/ops/repro-failures")
def ops_repro_failures(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return audit_repro_failures(conn)


@router.get("/ops/missing-fields")
def ops_missing_fields(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return audit_missing_fields(conn)
