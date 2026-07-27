from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.vulnerabilities import field_reviews
from ai4sec_platform.services import domain_items

DOMAIN = "vulnerabilities"


def materials(conn: sqlite3.Connection, limit: int = 50) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="material", limit=limit)


def today(conn: sqlite3.Connection, limit: int = 12) -> dict[str, Any]:
    materials_data = domain_items.list_items(conn, DOMAIN, item_type="material", limit=limit)
    events_data = _active_events(conn, limit)
    knowledge_data = domain_items.list_items(conn, DOMAIN, item_type="knowledge", limit=limit)
    pending_fields = _pending_field_count(knowledge_data["items"])
    return {
        "domain": DOMAIN,
        "kpis": {
            "new_poc_count": sum(1 for item in materials_data["items"] if (item.get("payload") or {}).get("material_type") == "poc_exploit"),
            "new_or_updated_event_count": len(events_data["items"]),
            "pending_field_review_count": pending_fields,
            "confirmed_knowledge_count": sum(1 for item in knowledge_data["items"] if item.get("status") == "confirmed"),
        },
        "workflow": ["先看新 PoC / Exploit", "按 CVE / 事件归并", "复核知识字段", "沉淀到知识库"],
        "priority_events": [_event_card(item) for item in events_data["items"]],
        "new_materials": materials_data["items"],
        "items": materials_data["items"],
        "next_workload": {"materials": len(materials_data["items"]), "events": len(events_data["items"]), "pending_fields": pending_fields, "knowledge": len(knowledge_data["items"])},
    }


def events(conn: sqlite3.Connection, limit: int = 50) -> dict[str, Any]:
    return _active_events(conn, limit)


def _active_events(conn: sqlite3.Connection, limit: int) -> dict[str, Any]:
    data = domain_items.list_items(conn, DOMAIN, item_type="event", limit=max(limit * 3, limit))
    items = [item for item in data["items"] if item.get("status") != "superseded"][:limit]
    return {"domain": DOMAIN, "count": len(items), "items": items}


def event_detail(conn: sqlite3.Connection, item_id: int) -> dict[str, Any] | None:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "event":
        return None
    material_ids = (item.get("payload") or {}).get("material_ids") or []
    materials_for_event = []
    for material_id in material_ids:
        material = domain_items.detail(conn, DOMAIN, int(material_id))
        if material:
            materials_for_event.append(material)
    item["materials"] = materials_for_event
    return item


def extractions(conn: sqlite3.Connection, limit: int = 50) -> dict[str, Any]:
    data = domain_items.list_items(conn, DOMAIN, item_type="knowledge", limit=limit)
    items = []
    for item in data["items"]:
        payload = item.get("payload") or {}
        items.append({**item, "field_reviews": payload.get("field_reviews") or {}, "pending_field_count": _pending_field_count([item])})
    return {"domain": DOMAIN, "count": len(items), "items": items}


def accept_field(conn: sqlite3.Connection, knowledge_id: int, field_name: str, reviewer: str = "shadow_operator", reason: str = "") -> dict[str, Any]:
    return field_reviews.accept_field(conn, knowledge_id, field_name, reviewer=reviewer, reason=reason)


def modify_field(conn: sqlite3.Connection, knowledge_id: int, field_name: str, value: Any, reviewer: str = "shadow_operator", reason: str = "") -> dict[str, Any]:
    return field_reviews.modify_field(conn, knowledge_id, field_name, value, reviewer=reviewer, reason=reason)


def reject_field(conn: sqlite3.Connection, knowledge_id: int, field_name: str, reviewer: str = "shadow_operator", reason: str = "") -> dict[str, Any]:
    return field_reviews.reject_field(conn, knowledge_id, field_name, reviewer=reviewer, reason=reason)


def _event_card(item: dict[str, Any]) -> dict[str, Any]:
    payload = item.get("payload") or {}
    return {
        "item_id": item.get("id"),
        "event_id": payload.get("event_id"),
        "title": item.get("title"),
        "kind": payload.get("kind"),
        "primary_cve_id": payload.get("primary_cve_id"),
        "cve_ids": payload.get("cve_ids") or [],
        "cwe_ids": payload.get("cwe_ids") or [],
        "status": item.get("status"),
        "score": item.get("score"),
        "material_count": len(payload.get("material_ids") or []),
        "knowledge_completeness": payload.get("knowledge_completeness", 0),
        "next_action": "复核事件归并" if payload.get("kind") in {"multi_cve_event", "knowledge_topic"} else "进入知识抽取",
    }


def _pending_field_count(items: list[dict[str, Any]]) -> int:
    count = 0
    for item in items:
        reviews = (item.get("payload") or {}).get("field_reviews") or {}
        count += sum(1 for review in reviews.values() if review.get("status") not in {"accepted", "modified"})
    return count
