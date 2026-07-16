from __future__ import annotations

import sqlite3

from ai4sec_platform.db import repositories as repo


def list_sources(conn: sqlite3.Connection, domain: str | None = None) -> dict:
    return repo.list_table(conn, "data_sources", domain=domain, limit=100)
