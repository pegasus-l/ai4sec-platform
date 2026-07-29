from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
from typing import Any

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.db.session import connect


def backup_database(destination: Path | None = None, settings: Settings | None = None) -> Path:
    cfg = settings or load_settings()
    target = destination or _default_backup_path(cfg)
    target = target.expanduser().resolve()
    if target == cfg.database_path.expanduser().resolve():
        raise ValueError("Backup destination must differ from the active database")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    temporary.unlink(missing_ok=True)
    try:
        with connect(cfg) as source, sqlite3.connect(temporary) as backup:
            source.backup(backup)
        verify_database(temporary)
        os.replace(temporary, target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return target


def restore_database(backup_path: Path, destination: Path, *, overwrite: bool = False) -> Path:
    source_path = backup_path.expanduser().resolve()
    target = destination.expanduser().resolve()
    if source_path == target:
        raise ValueError("Backup and restore destination must differ")
    verify_database(source_path)
    if target.exists() and not overwrite:
        raise FileExistsError(f"Restore destination already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.restore-{os.getpid()}")
    temporary.unlink(missing_ok=True)
    try:
        with _connect_read_only(source_path) as source, sqlite3.connect(temporary) as restored:
            source.backup(restored)
        verify_database(temporary)
        os.replace(temporary, target)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return target


def verify_database(path: Path) -> dict[str, Any]:
    database_path = path.expanduser().resolve()
    if not database_path.is_file():
        raise FileNotFoundError(database_path)
    with _connect_read_only(database_path) as conn:
        integrity_rows = [str(row[0]) for row in conn.execute("PRAGMA integrity_check").fetchall()]
        if integrity_rows != ["ok"]:
            raise ValueError(f"SQLite integrity check failed: {integrity_rows}")
        table_count = int(conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'").fetchone()[0])
    return {"path": str(database_path), "integrity": "ok", "table_count": table_count}


def _default_backup_path(settings: Settings) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return settings.output_dir / "backups" / f"ai4sec-platform-{timestamp}.db"


def _connect_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
