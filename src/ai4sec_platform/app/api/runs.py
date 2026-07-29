from __future__ import annotations

import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.core.ids import new_id
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.jobs import JobConflictError, enqueue_job, get_job, request_job_cancel
from ai4sec_platform.pipelines.registry import default_registry
from ai4sec_platform.pipelines.worker import PipelineWorker

router = APIRouter(prefix="/runs", tags=["runs"])


class RunPipelineRequest(BaseModel):
    pipeline_name: str = Field(default="news.legacy_raw_pipeline")
    reset: bool = False
    wait: bool = False
    params: dict[str, Any] = Field(default_factory=dict)


@router.get("/pipelines")
def pipelines() -> dict:
    return {"items": default_registry().list()}


@router.post("")
def start_run(request: RunPipelineRequest) -> dict:
    """Persist a run request for the single-host pipeline worker."""
    params = dict(request.params)
    params["reset"] = request.reset

    try:
        registry = default_registry()
        definition = registry.get(request.pipeline_name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    run_id = new_id("run")
    settings = load_settings()
    with connect(settings) as conn:
        init_db(conn)
        try:
            enqueue_job(
                conn,
                run_id=run_id,
                domain=definition.domain,
                pipeline_name=definition.name,
                params=params,
                total_steps=len(definition.steps),
                reset_requested=request.reset,
            )
        except JobConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    if request.wait:
        result = PipelineWorker(settings=settings, registry=registry).run_once(run_id=run_id)
        if result is None:
            raise HTTPException(status_code=409, detail="queued run was claimed by another worker")
        return result

    return {
        "run_id": run_id,
        "status": "queued",
        "pipeline_name": definition.name,
        "domain": definition.domain,
        "poll_url": f"/api/runs/{run_id}",
    }


@router.get("")
def runs(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return {"items": repo.list_table(conn, "pipeline_runs", limit=50)}


@router.get("/{run_id}")
def run_detail(run_id: str, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    run = conn.execute("SELECT * FROM pipeline_runs WHERE run_id = ?", (run_id,)).fetchone()
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    data = repo.row_to_dict(run)
    try:
        data["job"] = get_job(conn, run_id)
    except KeyError:
        data["job"] = None
    data["tasks"] = [repo.row_to_dict(row) for row in conn.execute("SELECT * FROM task_runs WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
    data["artifacts"] = [repo.row_to_dict(row) for row in conn.execute("SELECT * FROM artifacts WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
    summary = data.get("summary") or {}
    item_progress = summary.get("item_progress")
    child_run_ids = summary.get("child_run_ids") or []
    if child_run_ids and data.get("status") == "running":
        child = conn.execute("SELECT summary_json FROM pipeline_runs WHERE run_id = ?", (str(child_run_ids[-1]),)).fetchone()
        child_summary = repo.loads(child["summary_json"], {}) if child else {}
        item_progress = child_summary.get("item_progress") or item_progress
    progress = {
        "completed_steps": int(summary.get("completed_steps") or len(data["tasks"])),
        "total_steps": int(summary.get("total_steps") or 0),
        "current_step": str(summary.get("current_step") or ""),
    }
    if item_progress is not None:
        progress["item_progress"] = item_progress
    data["progress"] = progress
    return data


@router.post("/{run_id}/cancel")
def cancel_run(run_id: str, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return request_job_cancel(conn, run_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="run job not found") from exc
