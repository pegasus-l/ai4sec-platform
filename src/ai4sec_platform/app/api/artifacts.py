from __future__ import annotations

import sqlite3
from fastapi import APIRouter, Depends, HTTPException

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db import repositories as repo

router = APIRouter(prefix="/artifacts", tags=["artifacts"])


@router.get("/{artifact_id}")
def artifact_detail(artifact_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    row = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="artifact not found")
    return repo.row_to_dict(row)
