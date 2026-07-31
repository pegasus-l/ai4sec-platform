from __future__ import annotations

import sqlite3
import json
from typing import Any

from ai4sec_platform.core.time import utc_now


REPRO_TERMINAL_STATUSES = frozenset({"success", "partial", "failed", "timeout", "stopped"})
REPRO_STATUSES = frozenset({"queued", "running", *REPRO_TERMINAL_STATUSES, "cleaned"})
_REPRO_TRANSITIONS = {
    "queued": frozenset({"running", "stopped"}),
    "running": REPRO_TERMINAL_STATUSES,
    "success": frozenset({"cleaned"}),
    "partial": frozenset({"cleaned"}),
    "failed": frozenset({"cleaned"}),
    "timeout": frozenset({"cleaned"}),
    "stopped": frozenset({"cleaned"}),
    "cleaned": frozenset(),
}


class ReproStateTransitionError(RuntimeError):
    pass


def transition_repro_task(
    conn: sqlite3.Connection,
    *,
    task_id: int,
    status: str,
    fields: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = conn.execute("SELECT status FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
    if not row:
        raise ReproStateTransitionError(f"repro task not found: {task_id}")
    current = str(row["status"])
    if status not in REPRO_STATUSES:
        raise ReproStateTransitionError(f"unknown repro task status: {status}")
    if status != current and status not in _REPRO_TRANSITIONS.get(current, frozenset()):
        raise ReproStateTransitionError(f"invalid repro task transition: {current} -> {status}")
    updates = dict(fields or {})
    updates["status"] = status
    updates["updated_at"] = utc_now()
    assignments = ", ".join(f"{name} = ?" for name in updates)
    conn.execute(
        f"UPDATE capability_repro_tasks SET {assignments} WHERE id = ?",
        [*updates.values(), task_id],
    )
    updated = conn.execute("SELECT * FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
    return dict(updated)
from ai4sec_platform.pipelines.jobs import is_execution_kill_switch_active


def claim_next_repro_task(
    conn: sqlite3.Connection,
    *,
    worker_id: str,
    task_id: int | None = None,
) -> dict[str, Any] | None:
    now = utc_now()
    conn.execute("BEGIN IMMEDIATE")
    try:
        if is_execution_kill_switch_active(conn):
            conn.commit()
            return None
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


def register_repro_worker(
    conn: sqlite3.Connection,
    *,
    worker_id: str,
    hostname: str,
    pid: int,
    metadata: dict[str, Any] | None = None,
) -> None:
    now = utc_now()
    conn.execute(
        """
        INSERT INTO capability_repro_workers (
            worker_id, status, hostname, pid, started_at, heartbeat_at, stopped_at,
            current_task_id, metadata_json, updated_at
        ) VALUES (?, 'running', ?, ?, ?, ?, '', NULL, ?, ?)
        ON CONFLICT(worker_id) DO UPDATE SET
            status = 'running', hostname = excluded.hostname, pid = excluded.pid,
            started_at = excluded.started_at, heartbeat_at = excluded.heartbeat_at,
            stopped_at = '', current_task_id = NULL, metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at
        """,
        (worker_id, hostname, pid, now, now, json.dumps(metadata or {}, ensure_ascii=False), now),
    )
    conn.commit()


def heartbeat_repro_worker(
    conn: sqlite3.Connection,
    *,
    worker_id: str,
    current_task_id: int | None = None,
) -> bool:
    now = utc_now()
    cursor = conn.execute(
        """
        UPDATE capability_repro_workers
        SET status = 'running', heartbeat_at = ?, current_task_id = ?, updated_at = ?
        WHERE worker_id = ?
        """,
        (now, current_task_id, now, worker_id),
    )
    conn.commit()
    return cursor.rowcount == 1


def stop_repro_worker(conn: sqlite3.Connection, *, worker_id: str) -> bool:
    now = utc_now()
    cursor = conn.execute(
        """
        UPDATE capability_repro_workers
        SET status = 'stopped', stopped_at = ?, current_task_id = NULL, updated_at = ?
        WHERE worker_id = ?
        """,
        (now, now, worker_id),
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


def reconcile_interrupted_repro_tasks(
    conn: sqlite3.Connection,
    *,
    recovered_outcomes: dict[int, dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM capability_repro_tasks WHERE status = 'running'").fetchall()
    now = utc_now()
    outcomes = recovered_outcomes or {}
    for row in rows:
        task_id = int(row["id"])
        outcome = outcomes.get(task_id, {})
        status = str(outcome.get("status") or "failed")
        fields = {
            "result": str(
                outcome.get("result")
                or "repro worker interrupted; task was not replayed automatically"
            )[:10000],
            "finished_at": now,
            "worker_id": "",
            "heartbeat_at": "",
            "cleanup_requested": 1,
        }
        if outcome.get("report_json"):
            fields["report_json"] = str(outcome["report_json"])
        transition_repro_task(conn, task_id=task_id, status=status, fields=fields)
    conn.execute(
        "UPDATE capability_repro_tasks SET cleanup_requested = 1, updated_at = ? WHERE cleanup_requested = 2",
        (now,),
    )
    conn.commit()
    return [dict(row) for row in rows]
