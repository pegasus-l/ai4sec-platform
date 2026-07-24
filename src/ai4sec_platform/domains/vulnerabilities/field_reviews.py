from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo

FIELD_REVIEW_KEY = "field_reviews"


def accept_field(conn: sqlite3.Connection, knowledge_id: int, field_name: str, *, reviewer: str = "shadow_operator", reason: str = "") -> dict[str, Any]:
    return _apply_review(conn, knowledge_id, field_name, status="accepted", reviewer=reviewer, reason=reason)


def modify_field(conn: sqlite3.Connection, knowledge_id: int, field_name: str, value: Any, *, reviewer: str = "shadow_operator", reason: str = "") -> dict[str, Any]:
    return _apply_review(conn, knowledge_id, field_name, status="modified", reviewer=reviewer, reason=reason, value=value)


def reject_field(conn: sqlite3.Connection, knowledge_id: int, field_name: str, *, reviewer: str = "shadow_operator", reason: str = "") -> dict[str, Any]:
    return _apply_review(conn, knowledge_id, field_name, status="rejected", reviewer=reviewer, reason=reason)


def bind_field_evidence(conn: sqlite3.Connection, knowledge_id: int, field_name: str, evidence_ids: list[int], *, reviewer: str = "shadow_operator") -> dict[str, Any]:
    item = _knowledge(conn, knowledge_id)
    payload = dict(item.get("payload") or {})
    field_reviews = dict(payload.get(FIELD_REVIEW_KEY) or {})
    review = dict(field_reviews.get(field_name) or _default_review(payload, field_name))
    review.update({"evidence_ids": evidence_ids, "reviewer": reviewer, "reviewed_at": utc_now()})
    field_reviews[field_name] = review
    payload[FIELD_REVIEW_KEY] = field_reviews
    repo.update_domain_item(conn, item_id=knowledge_id, payload=payload, metrics={"field_review_count": len(field_reviews)})
    conn.commit()
    return {"knowledge_id": knowledge_id, "field_name": field_name, "review": review}


def _apply_review(
    conn: sqlite3.Connection,
    knowledge_id: int,
    field_name: str,
    *,
    status: str,
    reviewer: str,
    reason: str,
    value: Any = None,
) -> dict[str, Any]:
    item = _knowledge(conn, knowledge_id)
    payload = dict(item.get("payload") or {})
    field_reviews = dict(payload.get(FIELD_REVIEW_KEY) or {})
    review = dict(field_reviews.get(field_name) or _default_review(payload, field_name))
    if status == "modified":
        review["current_value"] = value
        payload[field_name] = value
    review.update({"status": status, "reviewer": reviewer, "reviewed_at": utc_now(), "reason": reason})
    field_reviews[field_name] = review
    payload[FIELD_REVIEW_KEY] = field_reviews
    item_status = _knowledge_status(payload)
    repo.update_domain_item(conn, item_id=knowledge_id, status=item_status, payload=payload, metrics={"field_review_count": len(field_reviews), "pending_field_count": _pending_count(payload)})
    if status == "rejected":
        repo.create_human_queue_item(
            conn,
            domain="vulnerabilities",
            item_id=knowledge_id,
            queue_type="knowledge_field_reanalysis",
            priority=2,
            reason=f"字段 {field_name} 已驳回，需要重分析。{reason}".strip(),
            payload={"field_name": field_name, "reviewer": reviewer},
        )
    conn.commit()
    return {"knowledge_id": knowledge_id, "field_name": field_name, "status": status, "review": review, "knowledge_status": item_status}


def _knowledge(conn: sqlite3.Connection, knowledge_id: int) -> dict[str, Any]:
    item = repo.get_domain_item(conn, "vulnerabilities", knowledge_id)
    if not item or item.get("item_type") != "knowledge":
        raise ValueError("knowledge item not found")
    return item


def _default_review(payload: dict[str, Any], field_name: str) -> dict[str, Any]:
    value = payload.get(field_name)
    return {"field_name": field_name, "model_value": value, "current_value": value, "status": "pending", "reviewer": "", "reviewed_at": "", "reason": "", "evidence_ids": []}


def _knowledge_status(payload: dict[str, Any]) -> str:
    reviews = payload.get(FIELD_REVIEW_KEY) or {}
    if any(review.get("status") == "rejected" for review in reviews.values()):
        return "reanalyze_required"
    required = required_fields(payload)
    if required and all((reviews.get(field) or {}).get("status") in {"accepted", "modified"} for field in required):
        return "confirmed"
    return "needs_review"


def _pending_count(payload: dict[str, Any]) -> int:
    reviews = payload.get(FIELD_REVIEW_KEY) or {}
    return sum(1 for field in required_fields(payload) if (reviews.get(field) or {}).get("status") not in {"accepted", "modified"})


def required_fields(payload: dict[str, Any]) -> list[str]:
    fields = ["vulnerability_type", "root_cause_pattern", "trigger_condition", "attack_entry", "mitigation_or_fix"]
    return [field for field in fields if field in payload]
