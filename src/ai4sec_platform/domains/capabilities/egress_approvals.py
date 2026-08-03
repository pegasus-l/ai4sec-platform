from __future__ import annotations

import re
import socket
import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.core.url_security import PublicUrlPolicy
from ai4sec_platform.domains.capabilities.repro_jobs import ReproStateTransitionError, transition_repro_task


_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ReproEgressApprovalError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def normalize_requested_domains(domains: list[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for raw_domain in domains:
        value = raw_domain.strip().casefold().rstrip(".")
        if not value or "://" in value or any(character in value for character in "/*:@?#[]"):
            raise ReproEgressApprovalError("invalid_domain", f"external egress must be an exact domain: {raw_domain}")
        try:
            domain = value.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ReproEgressApprovalError("invalid_domain", f"invalid external egress domain: {raw_domain}") from exc
        if len(domain) > 253 or "." not in domain or any(not _DOMAIN_LABEL.fullmatch(label) for label in domain.split(".")):
            raise ReproEgressApprovalError("invalid_domain", f"invalid external egress domain: {raw_domain}")
        try:
            socket.inet_pton(socket.AF_INET, domain)
        except OSError:
            try:
                socket.inet_pton(socket.AF_INET6, domain)
            except OSError:
                pass
            else:
                raise ReproEgressApprovalError("invalid_domain", "IP addresses cannot be requested for reproduction egress")
        else:
            raise ReproEgressApprovalError("invalid_domain", "IP addresses cannot be requested for reproduction egress")
        if domain not in normalized:
            normalized.append(domain)
    if len(normalized) > 20:
        raise ReproEgressApprovalError("too_many_domains", "at most 20 external egress domains may be requested")
    return tuple(normalized)


def create_egress_requests(
    conn: sqlite3.Connection,
    *,
    task_id: int,
    domains: tuple[str, ...],
    purpose: str,
    requested_by: str,
) -> list[dict[str, Any]]:
    now = utc_now()
    for domain in domains:
        conn.execute(
            """
            INSERT INTO capability_repro_egress_domains
                (task_id, domain, purpose, status, requested_by, created_at, updated_at)
            VALUES (?, ?, ?, 'pending', ?, ?, ?)
            """,
            (task_id, domain, purpose.strip(), requested_by.strip() or "operator", now, now),
        )
    return list_egress_requests(conn, task_id=task_id)


def list_egress_requests(conn: sqlite3.Connection, *, task_id: int) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            "SELECT * FROM capability_repro_egress_domains WHERE task_id = ? ORDER BY id",
            (task_id,),
        ).fetchall()
    ]


def approved_egress_domains(conn: sqlite3.Connection, *, task_id: int) -> tuple[str, ...]:
    rows = conn.execute(
        "SELECT domain FROM capability_repro_egress_domains WHERE task_id = ? AND status = 'approved' ORDER BY id",
        (task_id,),
    ).fetchall()
    return tuple(str(row["domain"]) for row in rows)


def review_egress_request(
    conn: sqlite3.Connection,
    *,
    task_id: int,
    request_id: int,
    decision: str,
    reviewed_by: str,
    reason: str,
    resolver=None,
) -> dict[str, Any]:
    if decision not in {"approved", "rejected"}:
        raise ReproEgressApprovalError("invalid_decision", "egress review decision must be approved or rejected")
    task = conn.execute("SELECT status FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
    if not task:
        raise ReproEgressApprovalError("task_not_found", "repro task not found")
    request = conn.execute(
        "SELECT * FROM capability_repro_egress_domains WHERE id = ? AND task_id = ?",
        (request_id, task_id),
    ).fetchone()
    if not request:
        raise ReproEgressApprovalError("request_not_found", "egress request not found")
    if str(task["status"]) != "awaiting_egress_approval" or str(request["status"]) != "pending":
        raise ReproEgressApprovalError("already_reviewed", "egress request is no longer pending")
    if decision == "approved":
        error = PublicUrlPolicy().validate(f"https://{request['domain']}/", resolve_dns=True, resolver=resolver)
        if error:
            raise ReproEgressApprovalError("unsafe_domain", f"external egress domain is unsafe or unavailable: {error}")
    now = utc_now()
    updated = conn.execute(
        """
        UPDATE capability_repro_egress_domains
        SET status = ?, reviewed_by = ?, review_reason = ?, reviewed_at = ?, updated_at = ?
        WHERE id = ? AND task_id = ? AND status = 'pending'
        """,
        (decision, reviewed_by.strip() or "operator", reason.strip(), now, now, request_id, task_id),
    )
    if updated.rowcount != 1:
        raise ReproEgressApprovalError("already_reviewed", "egress request is no longer pending")
    try:
        if decision == "rejected":
            transition_repro_task(conn, task_id=task_id, status="stopped", fields={"finished_at": now})
        else:
            pending = conn.execute(
                "SELECT COUNT(*) FROM capability_repro_egress_domains WHERE task_id = ? AND status = 'pending'",
                (task_id,),
            ).fetchone()[0]
            if int(pending) == 0:
                transition_repro_task(conn, task_id=task_id, status="queued")
    except ReproStateTransitionError as exc:
        raise ReproEgressApprovalError("state_conflict", str(exc)) from exc
    return dict(
        conn.execute(
            "SELECT * FROM capability_repro_egress_domains WHERE id = ? AND task_id = ?",
            (request_id, task_id),
        ).fetchone()
    )
