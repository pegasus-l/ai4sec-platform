from __future__ import annotations

from datetime import datetime, timedelta, timezone
import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo


ACTIVE_JOB_STATUSES = ("queued", "running")
FINAL_JOB_STATUSES = ("success", "failed", "cancelled")


class JobConflictError(RuntimeError):
    pass


def enqueue_job(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    domain: str,
    pipeline_name: str,
    params: dict[str, Any],
    total_steps: int,
    reset_requested: bool,
) -> dict[str, Any]:
    now = utc_now()
    try:
        conn.execute("BEGIN IMMEDIATE")
        conflict = _find_conflict(conn, pipeline_name=pipeline_name, reset_requested=reset_requested)
        if conflict:
            raise JobConflictError(_conflict_message(conflict, reset_requested=reset_requested))
        repo.create_pipeline_run(
            conn,
            run_id=run_id,
            domain=domain,
            pipeline_name=pipeline_name,
            status="queued",
            started_at=now,
            finished_at="",
            production_writes=False,
            summary={"params": params, "steps": [], "current_step": "", "completed_steps": 0, "total_steps": total_steps},
        )
        conn.execute(
            """
            INSERT INTO pipeline_jobs (
                run_id, domain, pipeline_name, params_json, reset_requested, status,
                queued_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?)
            """,
            (run_id, domain, pipeline_name, repo.dumps(params), int(reset_requested), now, now),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return get_job(conn, run_id)


def claim_next_job(
    conn: sqlite3.Connection,
    *,
    worker_id: str,
    run_id: str | None = None,
    lease_seconds: int = 45,
) -> dict[str, Any] | None:
    now = utc_now()
    lease_expires_at = _lease_deadline(lease_seconds)
    try:
        conn.execute("BEGIN IMMEDIATE")
        if run_id:
            row = conn.execute("SELECT * FROM pipeline_jobs WHERE run_id = ? AND status = 'queued'", (run_id,)).fetchone()
        else:
            row = conn.execute("SELECT * FROM pipeline_jobs WHERE status = 'queued' ORDER BY id LIMIT 1").fetchone()
        if not row:
            conn.commit()
            return None
        updated = conn.execute(
            """
            UPDATE pipeline_jobs
            SET status = 'running', attempt_count = attempt_count + 1, worker_id = ?,
                heartbeat_at = ?, lease_expires_at = ?, started_at = ?, updated_at = ?, error_message = ''
            WHERE run_id = ? AND status = 'queued'
            """,
            (worker_id, now, lease_expires_at, now, now, row["run_id"]),
        )
        if updated.rowcount != 1:
            conn.rollback()
            return None
        conn.execute(
            "UPDATE pipeline_workers SET current_run_id = ?, heartbeat_at = ?, updated_at = ? WHERE worker_id = ?",
            (row["run_id"], now, now, worker_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return get_job(conn, str(row["run_id"]))


def finish_job(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    worker_id: str,
    status: str,
    error_message: str = "",
) -> bool:
    if status not in FINAL_JOB_STATUSES:
        raise ValueError(f"Invalid final job status: {status}")
    now = utc_now()
    updated = conn.execute(
        """
        UPDATE pipeline_jobs
        SET status = ?, heartbeat_at = ?, lease_expires_at = '', error_message = ?, finished_at = ?, updated_at = ?
        WHERE run_id = ? AND worker_id = ? AND status = 'running'
        """,
        (status, now, error_message, now, now, run_id, worker_id),
    )
    conn.execute(
        "UPDATE pipeline_workers SET current_run_id = '', heartbeat_at = ?, updated_at = ? WHERE worker_id = ?",
        (now, now, worker_id),
    )
    conn.commit()
    return updated.rowcount == 1


def heartbeat_job(conn: sqlite3.Connection, *, run_id: str, worker_id: str, lease_seconds: int = 45) -> bool:
    now = utc_now()
    lease_expires_at = _lease_deadline(lease_seconds)
    updated = conn.execute(
        "UPDATE pipeline_jobs SET heartbeat_at = ?, lease_expires_at = ?, updated_at = ? WHERE run_id = ? AND worker_id = ? AND status = 'running'",
        (now, lease_expires_at, now, run_id, worker_id),
    )
    conn.execute(
        "UPDATE pipeline_workers SET status = 'running', heartbeat_at = ?, current_run_id = ?, updated_at = ? WHERE worker_id = ?",
        (now, run_id, now, worker_id),
    )
    conn.commit()
    return updated.rowcount == 1


def request_job_cancel(conn: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT status FROM pipeline_jobs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            raise KeyError(run_id)
        status = str(row["status"])
        now = utc_now()
        if status == "queued":
            conn.execute(
                """
                UPDATE pipeline_jobs
                SET status = 'cancelled', cancel_requested = 1, error_message = 'cancelled before execution',
                    finished_at = ?, updated_at = ?
                WHERE run_id = ? AND status = 'queued'
                """,
                (now, now, run_id),
            )
            pipeline_row = conn.execute("SELECT summary_json FROM pipeline_runs WHERE run_id = ?", (run_id,)).fetchone()
            summary = repo.loads(pipeline_row["summary_json"], {}) if pipeline_row else {}
            summary.update({"status": "cancelled", "error_message": "cancelled before execution"})
            conn.execute(
                "UPDATE pipeline_runs SET status = 'cancelled', finished_at = ?, summary_json = ? WHERE run_id = ?",
                (now, repo.dumps(summary), run_id),
            )
            outcome = "cancelled"
        elif status == "running":
            conn.execute(
                "UPDATE pipeline_jobs SET cancel_requested = 1, updated_at = ? WHERE run_id = ? AND status = 'running'",
                (now, run_id),
            )
            outcome = "cancellation_requested"
        else:
            outcome = status
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return {"run_id": run_id, "status": outcome}


def is_cancel_requested(conn: sqlite3.Connection, run_id: str) -> bool:
    row = conn.execute("SELECT cancel_requested FROM pipeline_jobs WHERE run_id = ?", (run_id,)).fetchone()
    return bool(row and row["cancel_requested"])


def reconcile_interrupted_jobs(conn: sqlite3.Connection, *, now: str | None = None) -> list[str]:
    cutoff = now or utc_now()
    rows = conn.execute(
        "SELECT run_id, worker_id FROM pipeline_jobs WHERE status = 'running' AND lease_expires_at != '' AND lease_expires_at <= ? ORDER BY id",
        (cutoff,),
    ).fetchall()
    run_ids = [str(row["run_id"]) for row in rows]
    if not run_ids:
        return []
    now = utc_now()
    placeholders = ",".join("?" for _ in run_ids)
    worker_ids = sorted({str(row["worker_id"]) for row in rows if row["worker_id"]})
    conn.execute(
        f"""
        UPDATE pipeline_jobs
        SET status = 'failed', heartbeat_at = ?, lease_expires_at = '', finished_at = ?,
            error_message = 'worker lease expired; manual retry required', updated_at = ?
        WHERE run_id IN ({placeholders})
        """,
        (now, now, now, *run_ids),
    )
    conn.execute(
        f"UPDATE pipeline_runs SET status = 'failed', finished_at = ? WHERE run_id IN ({placeholders})",
        (now, *run_ids),
    )
    if worker_ids:
        worker_placeholders = ",".join("?" for _ in worker_ids)
        conn.execute(
            f"UPDATE pipeline_workers SET status = 'lost', current_run_id = '', updated_at = ? WHERE worker_id IN ({worker_placeholders})",
            (cutoff, *worker_ids),
        )
    conn.commit()
    return run_ids


def register_worker(
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
        INSERT INTO pipeline_workers (
            worker_id, status, hostname, pid, started_at, heartbeat_at, stopped_at,
            current_run_id, metadata_json, updated_at
        ) VALUES (?, 'running', ?, ?, ?, ?, '', '', ?, ?)
        ON CONFLICT(worker_id) DO UPDATE SET
            status = 'running', hostname = excluded.hostname, pid = excluded.pid,
            started_at = excluded.started_at, heartbeat_at = excluded.heartbeat_at,
            stopped_at = '', current_run_id = '', metadata_json = excluded.metadata_json,
            updated_at = excluded.updated_at
        """,
        (worker_id, hostname, pid, now, now, repo.dumps(metadata or {}), now),
    )
    conn.commit()


def heartbeat_worker(conn: sqlite3.Connection, *, worker_id: str, current_run_id: str = "") -> bool:
    now = utc_now()
    updated = conn.execute(
        "UPDATE pipeline_workers SET status = 'running', heartbeat_at = ?, current_run_id = ?, updated_at = ? WHERE worker_id = ?",
        (now, current_run_id, now, worker_id),
    )
    conn.commit()
    return updated.rowcount == 1


def stop_worker(conn: sqlite3.Connection, *, worker_id: str) -> bool:
    now = utc_now()
    updated = conn.execute(
        "UPDATE pipeline_workers SET status = 'stopped', stopped_at = ?, current_run_id = '', updated_at = ? WHERE worker_id = ?",
        (now, now, worker_id),
    )
    conn.commit()
    return updated.rowcount == 1


def get_job(conn: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM pipeline_jobs WHERE run_id = ?", (run_id,)).fetchone()
    if not row:
        raise KeyError(run_id)
    data = repo.row_to_dict(row)
    data["params"] = repo.loads(data.pop("params_json"), {})
    data["reset_requested"] = bool(data["reset_requested"])
    data["cancel_requested"] = bool(data["cancel_requested"])
    return data


def _find_conflict(conn: sqlite3.Connection, *, pipeline_name: str, reset_requested: bool) -> sqlite3.Row | None:
    if reset_requested:
        return conn.execute(
            "SELECT run_id, pipeline_name, reset_requested FROM pipeline_jobs WHERE status IN ('queued', 'running') ORDER BY id LIMIT 1"
        ).fetchone()
    return conn.execute(
        """
        SELECT run_id, pipeline_name, reset_requested
        FROM pipeline_jobs
        WHERE status IN ('queued', 'running') AND (pipeline_name = ? OR reset_requested = 1)
        ORDER BY id LIMIT 1
        """,
        (pipeline_name,),
    ).fetchone()


def _conflict_message(conflict: sqlite3.Row, *, reset_requested: bool) -> str:
    if reset_requested:
        return f"reset run cannot start while another pipeline is active: {conflict['run_id']}"
    if bool(conflict["reset_requested"]):
        return f"pipeline cannot start while a reset run is active: {conflict['run_id']}"
    return f"pipeline already queued or running: {conflict['pipeline_name']}"


def _lease_deadline(seconds: int) -> str:
    value = datetime.now(timezone.utc) + timedelta(seconds=max(seconds, 1))
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")
