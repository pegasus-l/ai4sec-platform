from __future__ import annotations

import sqlite3

from ai4sec_platform.db import repositories as repo


def record_quality_audit(conn: sqlite3.Connection, *, domain: str, audit_type: str, status: str, summary: str, score: float | None = None, details: dict | None = None) -> None:
    repo.create_quality_audit(conn, domain=domain, audit_type=audit_type, status=status, score=score, summary=summary, details=details or {})
