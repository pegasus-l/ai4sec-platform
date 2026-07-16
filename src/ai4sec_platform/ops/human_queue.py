from __future__ import annotations

import sqlite3

from ai4sec_platform.db import repositories as repo


def enqueue(conn: sqlite3.Connection, *, domain: str, queue_type: str, reason: str, item_id: int | None = None, priority: int = 3, payload: dict | None = None) -> None:
    repo.create_human_queue_item(conn, domain=domain, item_id=item_id, queue_type=queue_type, priority=priority, reason=reason, payload=payload or {})
