from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now


def claim_next_repro_task(
    conn: sqlite3.Connection,
    *,
    worker_id: str,
    task_id: int | None = None,
) -> dict[str, Any] | None:
    now = utc_now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        sql = (
            "SELECT * FROM capability_repro_tasks "
            "WHERE status = 'queued' AND cancel_requested = 0 AND cleanup_requested = 0"
        )
        params: list[Any] = []
        if task_id is not None:
            sql += " AND id = ?"
            params.append(task_id)
        sql += " ORDER BY created_at, id LIMIT 1"
        row = conn.execute(sql, params).fetchone()
        if not row:
            conn.commit()
            return None
        cursor = conn.execute(
            """
            UPDATE capability_repro_tasks
            SET status = 'running', worker_id = ?, started_at = ?, heartbeat_at = ?, updated_at = ?
            WHERE id = ? AND status = 'queued' AND cancel_requested = 0 AND cleanup_requested = 0
            """,
            (worker_id, now, now, now, row["id"]),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return None
        claimed = conn.execute("SELECT * FROM capability_repro_tasks WHERE id = ?", (row["id"],)).fetchone()
        conn.commit()
        return dict(claimed)
    except Exception:
        conn.rollback()
        raise


def claim_cleanup_request(conn: sqlite3.Connection, *, task_id: int | None = None) -> dict[str, Any] | None:
    conn.execute("BEGIN IMMEDIATE")
    try:
        sql = "SELECT * FROM capability_repro_tasks WHERE cleanup_requested = 1 AND status != 'running'"
        params: list[Any] = []
        if task_id is not None:
            sql += " AND id = ?"
            params.append(task_id)
        sql += " ORDER BY updated_at, id LIMIT 1"
        row = conn.execute(sql, params).fetchone()
        if not row:
            conn.commit()
            return None
        cursor = conn.execute(
            "UPDATE capability_repro_tasks SET cleanup_requested = 2, updated_at = ? "
            "WHERE id = ? AND cleanup_requested = 1 AND status != 'running'",
            (utc_now(), row["id"]),
        )
        if cursor.rowcount != 1:
            conn.rollback()
            return None
        claimed = conn.execute("SELECT * FROM capability_repro_tasks WHERE id = ?", (row["id"],)).fetchone()
        conn.commit()
        return dict(claimed)
    except Exception:
        conn.rollback()
        raise


def heartbeat_repro_task(conn: sqlite3.Connection, *, task_id: int, worker_id: str) -> bool:
    now = utc_now()
    cursor = conn.execute(
        "UPDATE capability_repro_tasks SET heartbeat_at = ?, updated_at = ? "
        "WHERE id = ? AND worker_id = ? AND status = 'running'",
        (now, now, task_id, worker_id),
    )
    conn.commit()
    return cursor.rowcount == 1


def is_repro_cancel_requested(conn: sqlite3.Connection, task_id: int) -> bool:
    row = conn.execute(
        "SELECT cancel_requested FROM capability_repro_tasks WHERE id = ?",
        (task_id,),
    ).fetchone()
    return bool(row and row["cancel_requested"])


def request_repro_stop(conn: sqlite3.Connection, task_id: int) -> str | None:
    now = utc_now()
    queued = conn.execute(
        "UPDATE capability_repro_tasks SET status = 'stopped', cancel_requested = 1, "
        "finished_at = ?, updated_at = ? WHERE id = ? AND status = 'queued'",
        (now, now, task_id),
    )
    if queued.rowcount == 1:
        return "stopped"
    running = conn.execute(
        "UPDATE capability_repro_tasks SET cancel_requested = 1, updated_at = ? "
        "WHERE id = ? AND status = 'running'",
        (now, task_id),
    )
    if running.rowcount == 1:
        return "cancelling"
    row = conn.execute("SELECT status FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
    return str(row["status"]) if row else None


def request_repro_cleanup(conn: sqlite3.Connection, task_id: int) -> str | None:
    existing = conn.execute("SELECT status FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
    if not existing:
        return None
    if str(existing["status"]) == "cleaned":
        return "cleaned"
    now = utc_now()
    conn.execute(
        "UPDATE capability_repro_tasks SET cleanup_requested = 1, "
        "cancel_requested = CASE WHEN status = 'running' THEN 1 ELSE cancel_requested END, updated_at = ? WHERE id = ?",
        (now, task_id),
    )
    row = conn.execute("SELECT status FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
    return "cancelling" if row and row["status"] == "running" else "cleanup_queued"


def reconcile_interrupted_repro_tasks(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM capability_repro_tasks WHERE status = 'running'").fetchall()
    now = utc_now()
    if rows:
        conn.execute(
            """
            UPDATE capability_repro_tasks
            SET status = 'failed', result = 'repro worker interrupted; task was not replayed automatically',
                finished_at = ?, updated_at = ?, worker_id = '', heartbeat_at = ''
            WHERE status = 'running'
            """,
            (now, now),
        )
    conn.execute(
        "UPDATE capability_repro_tasks SET cleanup_requested = 1, updated_at = ? WHERE cleanup_requested = 2",
        (now,),
    )
    conn.commit()
    return [dict(row) for row in rows]
