from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo

DOMAINS = [
    ("news", "资讯洞察"),
    ("capabilities", "能力洞察"),
    ("threats", "威胁洞察"),
    ("vulnerabilities", "漏洞洞察"),
]


def overview(conn: sqlite3.Connection) -> dict[str, Any]:
    domain_cards = []
    for domain, label in DOMAINS:
        items = repo.list_domain_items(conn, domain, limit=5)
        queue_count = _count_queue(conn, domain)
        audits = repo.list_table(conn, "quality_audits", domain=domain, limit=3)
        domain_cards.append(
            {
                "domain": domain,
                "label": label,
                "item_count": repo.count_by_domain(conn, domain),
                "queue_count": queue_count,
                "top_items": items,
                "audit_status": audits[0]["status"] if audits else "unknown",
            }
        )
    return {
        "title": "AI4SEC TMG 平台概览",
        "production_writes": False,
        "domains": domain_cards,
        "recent_runs": repo.list_table(conn, "pipeline_runs", limit=8),
        "pending_queue_count": _count_queue(conn, None),
    }


def _count_queue(conn: sqlite3.Connection, domain: str | None) -> int:
    if domain:
        row = conn.execute("SELECT COUNT(*) AS count FROM human_queue_items WHERE domain = ? AND status = 'pending'", (domain,)).fetchone()
    else:
        row = conn.execute("SELECT COUNT(*) AS count FROM human_queue_items WHERE status = 'pending'").fetchone()
    return int(row["count"])
