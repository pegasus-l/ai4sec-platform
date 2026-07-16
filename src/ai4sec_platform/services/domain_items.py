from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo

DOMAIN_LABELS = {
    "news": "资讯洞察",
    "capabilities": "能力洞察",
    "threats": "威胁洞察",
    "vulnerabilities": "漏洞洞察",
}

TODAY_ITEM_TYPES = {
    "news": None,
    "capabilities": "capability",
    "threats": "target",
    "vulnerabilities": "material",
}


def list_items(conn: sqlite3.Connection, domain: str, *, item_type: str | None = None, limit: int = 50) -> dict[str, Any]:
    items = repo.list_domain_items(conn, domain, item_type=item_type, limit=limit)
    return {"domain": domain, "label": DOMAIN_LABELS.get(domain, domain), "count": len(items), "items": items}


def today(conn: sqlite3.Connection, domain: str, *, limit: int = 12) -> dict[str, Any]:
    return list_items(conn, domain, item_type=TODAY_ITEM_TYPES.get(domain), limit=limit)


def detail(conn: sqlite3.Connection, domain: str, item_id: int) -> dict[str, Any] | None:
    return repo.get_domain_item(conn, domain, item_id)
