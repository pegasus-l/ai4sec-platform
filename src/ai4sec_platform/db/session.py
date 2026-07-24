from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterator

from ai4sec_platform.core.config import Settings, load_settings


def connect(settings: Settings | None = None) -> sqlite3.Connection:
    cfg = settings or load_settings()
    cfg.database_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(cfg.database_path, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_connection() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()
