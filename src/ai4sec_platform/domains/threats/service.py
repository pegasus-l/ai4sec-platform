from __future__ import annotations

import sqlite3

from ai4sec_platform.services import domain_items

DOMAIN = "threats"


def targets(conn: sqlite3.Connection, limit: int = 50) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="target", limit=limit)
