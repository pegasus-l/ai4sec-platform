from __future__ import annotations

import sqlite3
import threading
import traceback
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.pipelines.registry import default_registry
from ai4sec_platform.pipelines.runner import PipelineRunner

router = APIRouter(prefix="/runs", tags=["runs"])


class RunPipelineRequest(BaseModel):
    pipeline_name: str = Field(default="news.legacy_raw_pipeline")
    reset: bool = False
    params: dict[str, Any] = Field(default_factory=dict)


@router.get("/pipelines")
def pipelines() -> dict:
    return {"items": default_registry().list()}


@router.post("")
def start_run(request: RunPipelineRequest) -> dict:
    """Start pipeline asynchronously — returns immediately, pipeline runs in background thread."""
    params = dict(request.params)
    params["reset"] = request.reset

    # Validate pipeline exists
    try:
        registry = default_registry()
        registry.get(request.pipeline_name)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    # Run in background thread (PipelineRunner creates its own DB connection)
    def _run_in_background():
        import sys
        print(f"[BG] Starting pipeline: {request.pipeline_name}", file=sys.stderr, flush=True)
        try:
            runner = PipelineRunner()
            result = runner.run(request.pipeline_name, params)
            print(f"[BG] Pipeline finished: {result.get('status', '?')}", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[BG] Pipeline CRASHED: {e}", file=sys.stderr, flush=True)
            traceback.print_exc()

    thread = threading.Thread(target=_run_in_background, daemon=True)
    thread.start()

    return {"status": "started", "pipeline": request.pipeline_name, "message": "Pipeline started in background. Poll GET /api/runs to track progress."}


@router.get("")
def runs(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return {"items": repo.list_table(conn, "pipeline_runs", limit=50)}


@router.get("/{run_id}")
def run_detail(run_id: str, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    run = conn.execute("SELECT * FROM pipeline_runs WHERE run_id = ?", (run_id,)).fetchone()
    if not run:
        raise HTTPException(status_code=404, detail="run not found")
    data = repo.row_to_dict(run)
    data["tasks"] = [repo.row_to_dict(row) for row in conn.execute("SELECT * FROM task_runs WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
    data["artifacts"] = [repo.row_to_dict(row) for row in conn.execute("SELECT * FROM artifacts WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
    return data
