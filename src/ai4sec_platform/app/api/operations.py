from __future__ import annotations

import sqlite3
from fastapi import APIRouter, Depends, Query

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.services import operations

router = APIRouter(prefix="/operations", tags=["operations"])


@router.get("/tasks")
def tasks(domain: str | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.tasks(conn, domain)


@router.get("/sources")
def sources(domain: str | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.sources(conn, domain)


@router.get("/rules")
def rules(domain: str | None = None) -> dict:
    return operations.rules(domain)


@router.get("/audits")
def audits(domain: str | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.audits(conn, domain)


@router.get("/human-queue")
def human_queue(domain: str | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.human_queue(conn, domain)


@router.get("/quality-findings")
def quality_findings(domain: str | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.audits(conn, domain)


@router.get("/queue-items")
def queue_items(domain: str | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.human_queue(conn, domain)
