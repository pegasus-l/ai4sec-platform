from __future__ import annotations

import sqlite3

from ai4sec_platform.services import domain_items

DOMAIN = "capabilities"


def today(conn: sqlite3.Connection, limit: int = 12) -> dict:
    return domain_items.today(conn, DOMAIN, limit=limit)


def list_items(conn: sqlite3.Connection, limit: int = 50) -> dict:
    return domain_items.list_items(conn, DOMAIN, limit=limit)
