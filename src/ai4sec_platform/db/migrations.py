from __future__ import annotations

import sqlite3

from ai4sec_platform.db.models import init_db


def apply_migrations(conn: sqlite3.Connection) -> None:
    init_db(conn)
