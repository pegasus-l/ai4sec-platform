from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db.maintenance import database_metrics

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "ai4sec-platform", "production_writes": False}


@router.get("/health/ready")
def readiness(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    conn.execute("SELECT 1").fetchone()
    return {
        "status": "ok",
        "service": "ai4sec-platform",
        "database": database_metrics(conn),
    }
