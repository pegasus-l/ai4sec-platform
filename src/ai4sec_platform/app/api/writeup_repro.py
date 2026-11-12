"""研究复现 API(T2)。一行任务 = "把这一篇 writeup 真的跑一遍"。

8 个端点:

    GET    /api/writeup-repro/tasks                    列表(按状态/结论筛, 服务端分页)
    GET    /api/writeup-repro/tasks/{id}               详情(含 spec / 证据 / 日志)
    POST   /api/writeup-repro/tasks                    建任务(同一素材幂等)
    POST   /api/writeup-repro/tasks/{id}/spec          调模型生成 spec 并校验
    PATCH  /api/writeup-repro/tasks/{id}/spec          人工改 spec(spec_source=human)
    POST   /api/writeup-repro/tasks/{id}/transition    状态机迁移(执行器调)
    POST   /api/writeup-repro/tasks/{id}/run           真的跑一遍(T3, 后台线程)
    POST   /api/writeup-repro/tasks/{id}/stop          停止正在跑的任务
    POST   /api/writeup-repro/tasks/{id}/cancel        人取消
    GET    /api/writeup-repro/stats                    漏斗统计

鉴权由 ``ASISSessionMiddleware`` 统一处理(``/api/*`` 一律 401), 这里不重复写。
"谁建的"取 ``current_user`` —— 不写空串, 空串在页面上分不清"没登录"和"没记录"。

错误口径(与领域层一致, 不在这里改判):

- 素材不可复现 / 已是终态 → **400**, 带原因;
- 模型不可用或返回不成形 → **503/502**, 且**不落任何结论** —— 下一轮重试;
- 原文没写清(repo 找不到引用)→ **200**, 任务落 ``cannot_repro + article_incomplete``。
  这是结论, 不是错误。
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from ai4sec_platform.app.dependencies import current_user, get_db
from ai4sec_platform.domains.capabilities.writeup_repro import executor
from ai4sec_platform.domains.capabilities.writeup_repro import spec as spec_module
from ai4sec_platform.domains.capabilities.writeup_repro import store, tasks

router = APIRouter(prefix="/writeup-repro", tags=["writeup-repro"])

_DOMAIN = "vulnerabilities"


class CreateTaskBody(BaseModel):
    material_id: int = Field(..., gt=0, description="domain_items.id, domain=vulnerabilities")
    case_id: int | None = Field(None, gt=0, description="关联的漏洞案例, 可空")
    trigger: str = Field("manual", max_length=32)


class SpecBody(BaseModel):
    """人工编辑的 spec(§5.3)。整份替换, 不做字段级合并 —— 半份新半份旧最难解释。"""

    spec: dict[str, Any]


class TransitionBody(BaseModel):
    to_state: str = Field(..., max_length=32)
    verdict: str = Field("", max_length=32)
    failure_reason: str = Field("", max_length=64)
    container_name: str | None = Field(None, max_length=200)
    session_id: str | None = Field(None, max_length=200)
    log: str | None = None
    duration_seconds: int | None = Field(None, ge=0)
    tool_calls: int | None = Field(None, ge=0)
    review_verdict: str | None = Field(None, max_length=32)
    review_reason: str | None = None
    recipe_id: int | None = Field(None, gt=0)
    evidence: dict[str, Any] | None = None
    recipe: dict[str, Any] | None = None


def _material(conn: sqlite3.Connection, material_id: int) -> dict[str, Any] | None:
    """读素材正文。列表接口一律 ``SELECT *`` 是库体积的老坑, 这里只要三列。"""
    conn.row_factory = conn.row_factory or sqlite3.Row
    row = conn.execute(
        "SELECT id, title, source_url, payload_json FROM domain_items "
        "WHERE id = ? AND domain = ? AND item_type = 'material'",
        (int(material_id), _DOMAIN),
    ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except ValueError:
        payload = {}
    return {
        "id": row["id"],
        "title": row["title"] or "",
        "url": row["source_url"] or "",
        "cleaned_text": str(payload.get("cleaned_text") or payload.get("markdown") or ""),
    }


def _must_get(conn: sqlite3.Connection, task_id: int) -> dict[str, Any]:
    task = tasks.get_task(conn, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail=f"任务 {task_id} 不存在")
    return task


# ---------------------------------------------------------------- 任务

@router.get("/tasks")
def list_tasks(
    status: str | None = Query(None, description="pending|spec_ready|queued|running|终态"),
    verdict: str | None = Query(None, description="success|partial|cannot_repro|failed|blocked"),
    material_id: int | None = Query(None, gt=0),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    if status and status not in tasks.STATES:
        raise HTTPException(status_code=400, detail=f"未知状态 {status!r}; 可选: {', '.join(tasks.STATES)}")
    if verdict and verdict not in tasks.VERDICT_STATES:
        raise HTTPException(status_code=400, detail=f"未知 verdict {verdict!r}; 可选: {', '.join(tasks.VERDICT_STATES)}")
    items, total = tasks.list_tasks(
        conn, status=status, verdict=verdict, material_id=material_id, limit=limit, offset=offset,
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/stats")
def task_stats(conn: sqlite3.Connection = Depends(get_db)) -> dict[str, Any]:
    """漏斗。``cannot_repro``(原文的锅)与 ``failed``(我们的锅)分列, 不合并。"""
    return tasks.stats(conn)


@router.get("/tasks/{task_id}")
def get_task(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict[str, Any]:
    return _must_get(conn, task_id)


@router.post("/tasks")
def create_task(
    body: CreateTaskBody,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """建任务。同一素材重复建**不插新行**, 返回已有的那一条(``created=false``)。"""
    try:
        task, created = tasks.create_task(
            conn, body.material_id, case_id=body.case_id,
            created_by=str(current_user(request).get("username") or ""), trigger=body.trigger,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"task": task, "created": created}


@router.post("/tasks/{task_id}/cancel")
def cancel_task(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict[str, Any]:
    try:
        return {"task": tasks.cancel(conn, task_id)}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/tasks/{task_id}/run")
def run_task(
    task_id: int,
    timeout: int | None = Query(None, ge=120, le=7200, description="本次执行的时间上限(秒)"),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """真的按 spec 跑一遍。**后台线程执行**, 立刻返回。

    三道前置检查都在这里挡住, 不让"没有 spec 的任务"白开一个会话:

    - 已是终态 → 400(要重跑得新开任务行, 否则证据与结论对不上);
    - 没有 steps → 400(先调 ``POST /tasks/{id}/spec``);
    - 已有执行线程 → 200 + ``started=false``(不重起, 不双跑)。
    """
    task = _must_get(conn, task_id)
    if task["status"] in tasks.TERMINAL_STATES:
        raise HTTPException(status_code=400, detail=f"任务 {task_id} 已是终态 {task['status']}, 不能重跑")
    if not (task.get("spec_json") or {}).get("steps"):
        raise HTTPException(status_code=400, detail="任务还没有可执行的 spec, 先调 POST /tasks/{id}/spec")
    started = executor.start_task(task_id, timeout=timeout)
    latest = tasks.get_task(conn, task_id) or task
    return {
        "started": started,
        "reason": "" if started else "已有执行线程在跑, 不重复启动",
        "task": latest,
    }


@router.post("/tasks/{task_id}/stop")
def stop_task(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict[str, Any]:
    """停止执行。只置进程内的停止标志, 线程在下一个心跳点退出并落 ``cancelled``。"""
    _must_get(conn, task_id)
    signalled = executor.stop_task(task_id)
    return {
        "signalled": signalled,
        "reason": "" if signalled else "进程内没有这条任务的执行线程(可能已结束, 或进程重启过)",
    }


@router.post("/tasks/{task_id}/transition")
def transition_task(
    task_id: int,
    body: TransitionBody,
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """状态机迁移。非法迁移 / verdict 与归因配错 → 400, 绝不静默写进去。"""
    fields = {
        key: value for key, value in {
            "container_name": body.container_name,
            "session_id": body.session_id,
            "log": body.log,
            "duration_seconds": body.duration_seconds,
            "tool_calls": body.tool_calls,
            "review_verdict": body.review_verdict,
            "review_reason": body.review_reason,
            "recipe_id": body.recipe_id,
            "evidence": body.evidence,
            "recipe": body.recipe,
        }.items() if value is not None
    }
    try:
        task = tasks.transition(
            conn, task_id, body.to_state,
            verdict=body.verdict, failure_reason=body.failure_reason, **fields,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"task": task}


# ---------------------------------------------------------------- spec

def _generate_and_store(conn: sqlite3.Connection, task: dict[str, Any]) -> dict[str, Any]:
    """生成 spec → 校验 → 按校验结论落库。三条出路各自不同, 见模块 docstring。

    模型不可用/返回不成形时**抛 503/502 且一行不写** —— 用一次网关抖动去判
    "原文不可复现", 就是把我们的故障记成作者的问题。
    """
    material = _material(conn, int(task["material_id"]))
    if material is None:
        raise HTTPException(status_code=404, detail=f"素材 {task['material_id']} 不存在")
    candidate = store.get_candidate(conn, int(task["material_id"]))
    outcome = spec_module.generate_spec(material, candidate)
    if outcome["status"] == "no_model":
        raise HTTPException(status_code=503, detail="没有可用的模型(当前是本地规则降级模式)")
    if outcome["status"] != "success":
        raise HTTPException(status_code=502, detail=f"spec 生成失败: {outcome.get('reason', '未知原因')}")

    check = spec_module.verify_spec(
        outcome["spec"], outcome["text"], title=outcome["title"], candidate=candidate or {},
    )
    if check.verdict == "invalid":
        # 模型说"文章写得够", 却给不出能对上的引用 —— **分不清是它抄错还是原文没写**。
        # 冒烟实测同一条素材两次结果不同(第一次抄漏一截, 第二次一字不差), 所以这里不下结论:
        # 计一次失败, 下一轮重试; 连着几次都建不出来才收成 spec_failed(我们的问题)。
        attempts = tasks.bump_spec_attempt(conn, int(task["id"]))
        if attempts >= tasks.MAX_SPEC_ATTEMPTS:
            return tasks.transition(
                conn, int(task["id"]), "spec_failed",
                log=f"连续 {attempts} 次没能建出可核对的 spec: {check.reason}",
            )
        raise HTTPException(status_code=502, detail=f"spec 不成形, 已丢弃(第 {attempts} 次, 下一轮重试): {check.reason}")
    if check.verdict == "article_incomplete":
        # 模型明确说原文没写清 —— 这是**结论**(作者的问题), 不重试。
        return tasks.transition(
            conn, int(task["id"]), "cannot_repro", failure_reason="article_incomplete",
            log=check.reason,
        )
    return tasks.set_spec(conn, int(task["id"]), check.spec, source="llm", notes=list(check.notes))


@router.post("/tasks/{task_id}/spec")
def generate_task_spec(task_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict[str, Any]:
    task = _must_get(conn, task_id)
    if task["status"] in tasks.TERMINAL_STATES:
        raise HTTPException(status_code=400, detail=f"任务 {task_id} 已是终态 {task['status']}")
    return {"task": _generate_and_store(conn, task)}


@router.patch("/tasks/{task_id}/spec")
def update_task_spec(
    task_id: int,
    body: SpecBody,
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """人工改 spec。``strict=False``: 引用对不上只记 note, 不拿 substring 检查否掉人。

    但**结构错误**(命令是占位符、成功信号判不了)仍然 400 —— 那种 spec 进了执行器
    也只会产生一次无法解释的失败。
    """
    task = _must_get(conn, task_id)
    if task["status"] in tasks.TERMINAL_STATES:
        raise HTTPException(status_code=400, detail=f"任务 {task_id} 已是终态 {task['status']}")
    material = _material(conn, int(task["material_id"]))
    if material is None:
        raise HTTPException(status_code=404, detail=f"素材 {task['material_id']} 不存在")
    candidate = store.get_candidate(conn, int(task["material_id"])) or {}
    check = spec_module.verify_spec(
        body.spec, material["cleaned_text"], title=material["title"],
        candidate=candidate, strict=False,
    )
    if check.verdict != "ok":
        raise HTTPException(status_code=400, detail=f"spec 不合规: {check.reason}")
    return {"task": tasks.set_spec(conn, task_id, check.spec, source="human", notes=list(check.notes))}
