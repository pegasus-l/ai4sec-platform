from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.services import frontend_v9

router = APIRouter(prefix="/frontend", tags=["frontend"])


@router.get("/v9")
def v9_page_contract(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return frontend_v9.page_contract(conn)


@router.get("/v9/files/{path:path}")
def v9_static_file_contract(path: str, conn: sqlite3.Connection = Depends(get_db)):
    data = frontend_v9.static_file_contract(conn, path)
    if data is None:
        raise HTTPException(status_code=404, detail="frontend contract file not found")
    return data
