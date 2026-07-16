from __future__ import annotations

import sqlite3
from fastapi import APIRouter, Depends, HTTPException

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db import repositories as repo

router = APIRouter(prefix="/runs", tags=["runs"])


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
