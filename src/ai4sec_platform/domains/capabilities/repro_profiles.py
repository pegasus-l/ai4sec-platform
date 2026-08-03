from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.domains.capabilities.repro_jobs import ReproStateTransitionError, transition_repro_task


REPRO_EXECUTION_PROFILES = frozenset({"standard", "nested_docker"})


class ReproProfileApprovalError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def normalize_execution_profile(value: str) -> str:
    profile = value.strip().casefold()
    if profile not in REPRO_EXECUTION_PROFILES:
        raise ReproProfileApprovalError("invalid_profile", "execution profile must be standard or nested_docker")
    return profile


def repro_profile_payload(conn: sqlite3.Connection, *, task_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        """
        SELECT id AS task_id, execution_profile, profile_approval_status, profile_reviewed_by,
               profile_review_reason, profile_reviewed_at, status AS task_status
        FROM capability_repro_tasks WHERE id = ?
        """,
        (task_id,),
    ).fetchone()
    return dict(row) if row else None


def review_nested_docker_profile(
    conn: sqlite3.Connection,
    *,
    task_id: int,
    decision: str,
    reviewed_by: str,
    reason: str,
) -> dict[str, Any]:
    if decision not in {"approved", "rejected"}:
        raise ReproProfileApprovalError("invalid_decision", "profile decision must be approved or rejected")
    row = conn.execute("SELECT * FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
    if not row:
        raise ReproProfileApprovalError("task_not_found", "repro task not found")
    if str(row["execution_profile"]) != "nested_docker":
        raise ReproProfileApprovalError("approval_not_required", "standard profile does not require nested Docker approval")
    if str(row["status"]) != "awaiting_profile_approval" or str(row["profile_approval_status"]) != "pending":
        raise ReproProfileApprovalError("already_reviewed", "nested Docker profile is no longer pending approval")
    if decision == "approved" and not reason.strip():
        raise ReproProfileApprovalError("reason_required", "nested Docker approval requires a risk acceptance reason")
    now = utc_now()
    updated = conn.execute(
        """
        UPDATE capability_repro_tasks
        SET profile_approval_status = ?, profile_reviewed_by = ?, profile_review_reason = ?,
            profile_reviewed_at = ?, updated_at = ?
        WHERE id = ? AND status = 'awaiting_profile_approval' AND profile_approval_status = 'pending'
        """,
        (decision, reviewed_by.strip() or "operator", reason.strip(), now, now, task_id),
    )
    if updated.rowcount != 1:
        raise ReproProfileApprovalError("already_reviewed", "nested Docker profile is no longer pending approval")
    try:
        if decision == "rejected":
            transition_repro_task(conn, task_id=task_id, status="stopped", fields={"finished_at": now})
        else:
            pending_egress = int(
                conn.execute(
                    "SELECT COUNT(*) FROM capability_repro_egress_domains WHERE task_id = ? AND status = 'pending'",
                    (task_id,),
                ).fetchone()[0]
            )
            transition_repro_task(
                conn,
                task_id=task_id,
                status="awaiting_egress_approval" if pending_egress else "queued",
            )
    except ReproStateTransitionError as exc:
        raise ReproProfileApprovalError("state_conflict", str(exc)) from exc
    return repro_profile_payload(conn, task_id=task_id) or {}
