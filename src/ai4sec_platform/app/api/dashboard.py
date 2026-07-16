from __future__ import annotations

import sqlite3
from fastapi import APIRouter, Depends

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.services.dashboard import overview

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/overview")
def dashboard_overview(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return overview(conn)
