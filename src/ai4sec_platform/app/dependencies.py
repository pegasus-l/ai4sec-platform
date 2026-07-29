from __future__ import annotations

from collections.abc import Iterator
import sqlite3

from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect


def get_db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    init_db(conn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
