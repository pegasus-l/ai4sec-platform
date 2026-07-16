from __future__ import annotations

import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Query

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.services import domain_items
from ai4sec_platform.services import operations

router = APIRouter(prefix="/news", tags=["news"])
DOMAIN = "news"


@router.get("/today")
def today(limit: int = Query(12, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.today(conn, DOMAIN, limit=limit)


@router.get("/items")
def items(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, limit=limit)


@router.get("/items/{item_id}")
def item_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="news item not found")
    return item


@router.get("/sources")
def sources(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.sources(conn, DOMAIN)


@router.get("/audits")
def audits(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.audits(conn, DOMAIN)
