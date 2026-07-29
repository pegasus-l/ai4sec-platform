from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Request, Response

from ai4sec_platform.core.config import Settings
from ai4sec_platform.db.maintenance import database_metrics, database_write_probe
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "ai4sec-platform", "production_writes": False}


@router.get("/health/ready")
def readiness(request: Request, response: Response) -> dict:
    settings: Settings = request.app.state.settings
    try:
        with connect(settings) as conn:
            init_db(conn)
            conn.execute("SELECT 1").fetchone()
            database = database_metrics(conn, settings)
            database["write_probe"] = database_write_probe(
                conn,
                timeout_ms=settings.readiness_write_timeout_ms,
            )
        return {"status": "ok", "service": "ai4sec-platform", "database": database}
    except (sqlite3.Error, RuntimeError) as exc:
        response.status_code = 503
        return {
            "status": "not_ready",
            "service": "ai4sec-platform",
            "database": {
                "writable": False,
                "error": _database_error_code(exc),
            },
        }


def _database_error_code(error: Exception) -> str:
    message = str(error).lower()
    if "locked" in message or "busy" in message:
        return "database_locked"
    if "readonly" in message or "read-only" in message:
        return "database_read_only"
    if isinstance(error, RuntimeError):
        return "database_schema_error"
    return "database_error"
