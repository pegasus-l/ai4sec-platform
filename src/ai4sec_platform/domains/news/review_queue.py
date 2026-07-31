from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo

QUEUE_TYPE = "news_model_schema"


def queue_schema_failure(
    conn: sqlite3.Connection,
    *,
    stage: str,
    item: dict[str, Any],
    request_key: str,
    run_id: str,
    prompt_version: str,
    errors: list[str],
    fallback: dict[str, Any],
) -> int:
    return repo.create_human_queue_item(
        conn,
        domain="news",
        item_id=None,
        queue_type=QUEUE_TYPE,
        priority=2,
        reason="；".join(errors),
        dedupe_key=request_key,
        payload={
            "stage": stage,
            "item_key": str(item.get("item_key") or ""),
            "title": str(item.get("title") or ""),
            "url": str(item.get("url") or ""),
            "source_type": str(item.get("source_type") or ""),
            "request_key": request_key,
            "run_id": run_id,
            "prompt_version": prompt_version,
            "schema_errors": errors,
            "fallback": fallback,
        },
    )


def resolve_schema_failure(conn: sqlite3.Connection, request_key: str) -> None:
    conn.execute(
        "UPDATE human_queue_items SET status = 'resolved', updated_at = ? "
        "WHERE domain = 'news' AND queue_type = ? AND dedupe_key = ? AND status = 'pending'",
        (utc_now(), QUEUE_TYPE, request_key),
    )


def is_rejected(conn: sqlite3.Connection, request_key: str) -> bool:
    row = conn.execute(
        "SELECT status FROM human_queue_items WHERE domain = 'news' AND queue_type = ? AND dedupe_key = ? ORDER BY id DESC LIMIT 1",
        (QUEUE_TYPE, request_key),
    ).fetchone()
    return bool(row and row["status"] == "rejected")


def list_items(conn: sqlite3.Connection, status: str = "pending", limit: int = 100) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM human_queue_items WHERE domain = 'news' AND queue_type = ? AND status = ? ORDER BY priority, id DESC LIMIT ?",
        (QUEUE_TYPE, status, limit),
    ).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["payload"] = repo.loads(item.pop("payload_json"), {})
        result.append(item)
    return result


def set_item_status(conn: sqlite3.Connection, item_id: int, action: str) -> dict[str, Any] | None:
    status = {"reject": "rejected", "reopen": "pending"}.get(action)
    if not status:
        raise ValueError("unsupported review queue action")
    row = conn.execute(
        "SELECT * FROM human_queue_items WHERE id = ? AND domain = 'news' AND queue_type = ?",
        (item_id, QUEUE_TYPE),
    ).fetchone()
    if not row:
        return None
    conn.execute("UPDATE human_queue_items SET status = ?, updated_at = ? WHERE id = ?", (status, utc_now(), item_id))
    updated = conn.execute("SELECT * FROM human_queue_items WHERE id = ?", (item_id,)).fetchone()
    item = dict(updated)
    item["payload"] = repo.loads(item.pop("payload_json"), {})
    return item
