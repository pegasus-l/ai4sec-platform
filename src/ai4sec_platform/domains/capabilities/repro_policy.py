from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
import sqlite3
from typing import Any

from ai4sec_platform.core.env import load_env_file
from ai4sec_platform.core.time import utc_now


load_env_file()


REPRO_MAX_CONCURRENT_TASKS = int(os.environ.get("REPRO_MAX_CONCURRENT_TASKS", "1"))
REPRO_MAX_QUEUED_TASKS = int(os.environ.get("REPRO_MAX_QUEUED_TASKS", "20"))
REPRO_MAX_ATTEMPTS_PER_ITEM_24H = int(os.environ.get("REPRO_MAX_ATTEMPTS_PER_ITEM_24H", "3"))
REPRO_MAX_AUTOMATIC_RETRIES = int(os.environ.get("REPRO_MAX_AUTOMATIC_RETRIES", "0"))
REPRO_WORKER_HEARTBEAT_SECONDS = int(os.environ.get("REPRO_WORKER_HEARTBEAT_SECONDS", "10"))
REPRO_WORKER_STALE_SECONDS = int(os.environ.get("REPRO_WORKER_STALE_SECONDS", "30"))


class ReproQuotaExceededError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validate_repro_queue_limits() -> None:
    if REPRO_MAX_CONCURRENT_TASKS != 1:
        raise RuntimeError("REPRO_MAX_CONCURRENT_TASKS must be 1 for the single-host locked Repro Worker")
    if not 1 <= REPRO_MAX_QUEUED_TASKS <= 1000:
        raise RuntimeError("REPRO_MAX_QUEUED_TASKS must be between 1 and 1000")
    if not 1 <= REPRO_MAX_ATTEMPTS_PER_ITEM_24H <= 20:
        raise RuntimeError("REPRO_MAX_ATTEMPTS_PER_ITEM_24H must be between 1 and 20")
    if REPRO_MAX_AUTOMATIC_RETRIES != 0:
        raise RuntimeError("REPRO_MAX_AUTOMATIC_RETRIES must remain 0 until task execution is safely replayable")
    if not 1 <= REPRO_WORKER_HEARTBEAT_SECONDS <= 300:
        raise RuntimeError("REPRO_WORKER_HEARTBEAT_SECONDS must be between 1 and 300")
    if not max(10, REPRO_WORKER_HEARTBEAT_SECONDS * 2) <= REPRO_WORKER_STALE_SECONDS <= 3600:
        raise RuntimeError("REPRO_WORKER_STALE_SECONDS must be between 10 and 3600")


def enqueue_repro_task(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    repo_url: str,
    trigger: str,
) -> int:
    validate_repro_queue_limits()
    now = utc_now()
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    cursor = conn.execute(
        """
        INSERT INTO capability_repro_tasks (item_id, repo_url, status, created_at, updated_at, trigger)
        SELECT ?, ?, 'queued', ?, ?, ?
        WHERE NOT EXISTS (
            SELECT 1 FROM capability_repro_tasks WHERE item_id = ? AND status IN ('queued', 'running')
        )
        AND (SELECT COUNT(*) FROM capability_repro_tasks WHERE status = 'queued') < ?
        AND (
            SELECT COUNT(*) FROM capability_repro_tasks WHERE item_id = ? AND created_at >= ?
        ) < ?
        """,
        (
            item_id,
            repo_url,
            now,
            now,
            trigger,
            item_id,
            REPRO_MAX_QUEUED_TASKS,
            item_id,
            cutoff,
            REPRO_MAX_ATTEMPTS_PER_ITEM_24H,
        ),
    )
    if cursor.rowcount == 1:
        return int(cursor.lastrowid)
    usage = repro_quota_usage(conn, item_id=item_id, cutoff=cutoff)
    if usage["item_active"]:
        raise ReproQuotaExceededError("item_active", "an active repro task already exists for this item")
    if usage["queued"] >= REPRO_MAX_QUEUED_TASKS:
        raise ReproQuotaExceededError("queue_full", "the capability reproduction queue is full")
    raise ReproQuotaExceededError(
        "item_attempt_limit",
        f"this item reached the {REPRO_MAX_ATTEMPTS_PER_ITEM_24H} attempts per 24 hours limit",
    )


def repro_quota_usage(
    conn: sqlite3.Connection,
    *,
    item_id: int | None = None,
    cutoff: str | None = None,
) -> dict[str, Any]:
    cutoff = cutoff or (
        datetime.now(timezone.utc) - timedelta(hours=24)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    counts = conn.execute(
        """
        SELECT
            SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued,
            SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) AS running
        FROM capability_repro_tasks
        """
    ).fetchone()
    item_active = 0
    item_attempts = 0
    if item_id is not None:
        item_counts = conn.execute(
            """
            SELECT
                SUM(CASE WHEN status IN ('queued', 'running') THEN 1 ELSE 0 END) AS active,
                SUM(CASE WHEN created_at >= ? THEN 1 ELSE 0 END) AS attempts
            FROM capability_repro_tasks WHERE item_id = ?
            """,
            (cutoff, item_id),
        ).fetchone()
        item_active = int(item_counts["active"] or 0)
        item_attempts = int(item_counts["attempts"] or 0)
    return {
        "queued": int(counts["queued"] or 0),
        "running": int(counts["running"] or 0),
        "item_active": item_active,
        "item_attempts_24h": item_attempts,
        "cutoff": cutoff,
    }


def repro_limits_payload(conn: sqlite3.Connection) -> dict[str, Any]:
    validate_repro_queue_limits()
    return {
        "limits": {
            "max_concurrent_tasks": REPRO_MAX_CONCURRENT_TASKS,
            "max_queued_tasks": REPRO_MAX_QUEUED_TASKS,
            "max_attempts_per_item_24h": REPRO_MAX_ATTEMPTS_PER_ITEM_24H,
            "max_automatic_retries": REPRO_MAX_AUTOMATIC_RETRIES,
            "worker_heartbeat_seconds": REPRO_WORKER_HEARTBEAT_SECONDS,
        },
        "usage": repro_quota_usage(conn),
    }


def repro_worker_status_payload(conn: sqlite3.Connection) -> dict[str, Any]:
    validate_repro_queue_limits()
    now = datetime.now(timezone.utc)
    rows = conn.execute(
        "SELECT worker_id, status, heartbeat_at, stopped_at, current_task_id "
        "FROM capability_repro_workers ORDER BY updated_at DESC LIMIT 20"
    ).fetchall()
    workers: list[dict[str, Any]] = []
    healthy = 0
    for row in rows:
        heartbeat_at = str(row["heartbeat_at"] or "")
        age_seconds: int | None = None
        if heartbeat_at:
            try:
                heartbeat = datetime.fromisoformat(heartbeat_at.replace("Z", "+00:00"))
                age_seconds = max(0, int((now - heartbeat).total_seconds()))
            except ValueError:
                age_seconds = None
        registered_running = str(row["status"]) == "running"
        is_healthy = registered_running and age_seconds is not None and age_seconds <= REPRO_WORKER_STALE_SECONDS
        effective_status = "healthy" if is_healthy else "stale" if registered_running else "stopped"
        healthy += int(is_healthy)
        workers.append(
            {
                "worker_id": str(row["worker_id"]),
                "status": effective_status,
                "heartbeat_at": heartbeat_at,
                "heartbeat_age_seconds": age_seconds,
                "current_task_id": row["current_task_id"],
                "stopped_at": str(row["stopped_at"] or ""),
            }
        )
    return {
        "status": "ready" if healthy else "unavailable",
        "healthy_workers": healthy,
        "stale_after_seconds": REPRO_WORKER_STALE_SECONDS,
        "workers": workers,
    }
