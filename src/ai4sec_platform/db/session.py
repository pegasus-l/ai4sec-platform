from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Iterator

from ai4sec_platform.core.config import Settings, load_settings


def connect(settings: Settings | None = None) -> sqlite3.Connection:
    cfg = settings or load_settings()
    _prepare_database_directory(cfg.database_path)
    conn = sqlite3.connect(cfg.database_path, timeout=cfg.sqlite_busy_timeout_ms / 1000, check_same_thread=False)
    try:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute(f"PRAGMA synchronous = {cfg.sqlite_synchronous}")
        conn.execute(f"PRAGMA busy_timeout = {cfg.sqlite_busy_timeout_ms}")
        conn.execute(f"PRAGMA wal_autocheckpoint = {cfg.sqlite_wal_autocheckpoint_pages}")
        _restrict_database_files(cfg.database_path)
        return conn
    except Exception:
        conn.close()
        raise


def _prepare_database_directory(database_path: Path) -> None:
    directory = database_path.parent
    directory.mkdir(mode=0o750, parents=True, exist_ok=True)
    if not directory.is_dir():
        raise RuntimeError(f"SQLite database parent is not a directory: {directory}")
    try:
        directory.chmod(0o750)
    except OSError as exc:
        raise RuntimeError(f"Cannot enforce SQLite directory permissions on {directory}: {exc}") from exc


def _restrict_database_files(database_path: Path) -> None:
    for path in (database_path, Path(f"{database_path}-wal"), Path(f"{database_path}-shm")):
        if not path.exists():
            continue
        try:
            os.chmod(path, 0o640)
        except OSError as exc:
            raise RuntimeError(f"Cannot enforce SQLite file permissions on {path}: {exc}") from exc


def get_connection() -> Iterator[sqlite3.Connection]:
    conn = connect()
    try:
        yield conn
    finally:
        conn.close()
