from __future__ import annotations

import sqlite3
import threading
import traceback
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.core.ids import new_id
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.registry import default_registry
from ai4sec_platform.pipelines.runner import PipelineRunner

router = APIRouter(prefix="/runs", tags=["runs"])


class RunPipelineRequest(BaseModel):
    pipeline_name: str = Field(default="news.legacy_raw_pipeline")
    reset: bool = False
    wait: bool = False
    params: dict[str, Any] = Field(default_factory=dict)


_active_runs_lock = threading.Lock()
_active_runs: dict[str, bool] = {}


@router.get("/pipelines")
def pipelines() -> dict:
    return {"items": default_registry().list()}


@router.post("")
def start_run(request: RunPipelineRequest) -> dict:
    """Reserve a run ID, then execute synchronously or in a background thread."""
    params = dict(request.params)
    params["reset"] = request.reset

    # Validate pipeline exists
    try:
        registry = default_registry()
        definition = registry.get(request.pipeline_name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    run_id = new_id("run")
    _reserve_run_slot(run_id, reset=request.reset)
    try:
        _create_queued_run(
            run_id=run_id,
            domain=definition.domain,
            pipeline_name=definition.name,
            params=params,
            total_steps=len(definition.steps),
        )
    except Exception:
        _release_run_slot(run_id)
        raise

    def execute() -> dict[str, Any]:
        import sys
        print(f"[BG] Starting pipeline: {request.pipeline_name}", file=sys.stderr, flush=True)
        try:
            runner = PipelineRunner()
            result = runner.run(request.pipeline_name, params, run_id=run_id)
            print(f"[BG] Pipeline finished: {result.get('status', '?')}", file=sys.stderr, flush=True)
            return result
        except Exception as exc:
            _mark_run_failed(run_id, definition.domain, definition.name, params, str(exc))
            print(f"[BG] Pipeline CRASHED: {exc}", file=sys.stderr, flush=True)
            traceback.print_exc()
            return {"run_id": run_id, "pipeline_name": definition.name, "domain": definition.domain, "status": "failed", "summary": {"params": params, "status": "failed", "error_message": str(exc)}}
        finally:
            _release_run_slot(run_id)

    if request.wait:
        return execute()

    thread = threading.Thread(target=execute, daemon=True, name=f"pipeline-{run_id}")
    thread.start()

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
        with _active_runs_lock:
            if run_id in _active_runs:
                return {"run_id": run_id, "status": "running", "tasks": [], "artifacts": [], "progress": {"completed_steps": 0, "total_steps": 0, "current_step": ""}}
        raise HTTPException(status_code=404, detail="run not found")
    data = repo.row_to_dict(run)
    data["tasks"] = [repo.row_to_dict(row) for row in conn.execute("SELECT * FROM task_runs WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
    data["artifacts"] = [repo.row_to_dict(row) for row in conn.execute("SELECT * FROM artifacts WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
    summary = data.get("summary") or {}
    item_progress = summary.get("item_progress")
    child_run_ids = summary.get("child_run_ids") or []
    if child_run_ids and data.get("status") == "running":
        child = conn.execute("SELECT summary_json FROM pipeline_runs WHERE run_id = ?", (str(child_run_ids[-1]),)).fetchone()
        child_summary = repo.loads(child["summary_json"], {}) if child else {}
        item_progress = child_summary.get("item_progress") or item_progress
    data["progress"] = {
        "completed_steps": int(summary.get("completed_steps") or len(data["tasks"])),
        "total_steps": int(summary.get("total_steps") or 0),
        "current_step": str(summary.get("current_step") or ""),
        "item_progress": item_progress,
    }
    return data


def _reserve_run_slot(run_id: str, *, reset: bool) -> None:
    with _active_runs_lock:
        reset_active = any(_active_runs.values())
        if reset and _active_runs:
            raise HTTPException(status_code=409, detail="reset run cannot start while another pipeline is active")
        if not reset and reset_active:
            raise HTTPException(status_code=409, detail="pipeline cannot start while a reset run is active")
        _active_runs[run_id] = reset


def _release_run_slot(run_id: str) -> None:
    with _active_runs_lock:
        _active_runs.pop(run_id, None)


def _create_queued_run(*, run_id: str, domain: str, pipeline_name: str, params: dict[str, Any], total_steps: int) -> None:
    settings = load_settings()
    with connect(settings) as conn:
        init_db(conn)
        repo.create_pipeline_run(
            conn,
            run_id=run_id,
            domain=domain,
            pipeline_name=pipeline_name,
            status="queued",
            started_at=utc_now(),
            finished_at="",
            production_writes=False,
            summary={"params": params, "steps": [], "current_step": "", "completed_steps": 0, "total_steps": total_steps},
        )
        conn.commit()


def _mark_run_failed(run_id: str, domain: str, pipeline_name: str, params: dict[str, Any], error_message: str) -> None:
    settings = load_settings()
    with connect(settings) as conn:
        init_db(conn)
        repo.create_pipeline_run(
            conn,
            run_id=run_id,
            domain=domain,
            pipeline_name=pipeline_name,
            status="failed",
            started_at="",
            finished_at=utc_now(),
            production_writes=False,
            summary={"params": params, "steps": [], "current_step": "", "completed_steps": 0, "total_steps": 0, "status": "failed", "error_message": error_message},
        )
        conn.commit()
