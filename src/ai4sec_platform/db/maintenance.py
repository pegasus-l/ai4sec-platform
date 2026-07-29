from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import sqlite3
import time
from typing import Any

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.db.migrations import current_schema_version
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


def database_metrics(conn: sqlite3.Connection, settings: Settings | None = None) -> dict[str, Any]:
    cfg = settings or load_settings()
    database_path = cfg.database_path.expanduser().resolve()
    page_size = int(conn.execute("PRAGMA page_size").fetchone()[0])
    page_count = int(conn.execute("PRAGMA page_count").fetchone()[0])
    freelist_count = int(conn.execute("PRAGMA freelist_count").fetchone()[0])
    return {
        "path": str(database_path),
        "database_bytes": _file_size(database_path),
        "wal_bytes": _file_size(Path(f"{database_path}-wal")),
        "shm_bytes": _file_size(Path(f"{database_path}-shm")),
        "journal_mode": str(conn.execute("PRAGMA journal_mode").fetchone()[0]),
        "synchronous": int(conn.execute("PRAGMA synchronous").fetchone()[0]),
        "busy_timeout_ms": int(conn.execute("PRAGMA busy_timeout").fetchone()[0]),
        "page_size": page_size,
        "page_count": page_count,
        "freelist_count": freelist_count,
        "allocated_bytes": page_size * page_count,
        "free_bytes": page_size * freelist_count,
        "schema_version": current_schema_version(conn),
    }


def database_write_probe(conn: sqlite3.Connection, *, timeout_ms: int = 1_000) -> dict[str, Any]:
    previous_timeout = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])
    started = time.perf_counter()
    savepoint_started = False
    try:
        conn.execute(f"PRAGMA busy_timeout = {max(timeout_ms, 1)}")
        conn.execute("SAVEPOINT readiness_write_probe")
        savepoint_started = True
        conn.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (-1, ?, ?, ?)",
            ("readiness_write_probe", "rolled_back", datetime.now(timezone.utc).isoformat()),
        )
        conn.execute("ROLLBACK TO readiness_write_probe")
        conn.execute("RELEASE readiness_write_probe")
        savepoint_started = False
        residue = conn.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = -1").fetchone()[0]
        if residue:
            raise sqlite3.DatabaseError("readiness write probe left a persistent row")
        return {
            "writable": True,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "timeout_ms": max(timeout_ms, 1),
        }
    except sqlite3.Error:
        if savepoint_started:
            try:
                conn.execute("ROLLBACK TO readiness_write_probe")
                conn.execute("RELEASE readiness_write_probe")
            except sqlite3.Error:
                conn.rollback()
        raise
    finally:
        conn.execute(f"PRAGMA busy_timeout = {previous_timeout}")


def checkpoint_wal(mode: str = "PASSIVE", settings: Settings | None = None) -> dict[str, Any]:
    checkpoint_mode = mode.strip().upper()
    if checkpoint_mode not in {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}:
        raise ValueError(f"Unsupported WAL checkpoint mode: {mode}")
    cfg = settings or load_settings()
    with connect(cfg) as conn:
        row = conn.execute(f"PRAGMA wal_checkpoint({checkpoint_mode})").fetchone()
        metrics = database_metrics(conn, cfg)
    return {
        "mode": checkpoint_mode,
        "busy": int(row[0]),
        "log_frames": int(row[1]),
        "checkpointed_frames": int(row[2]),
        "wal_bytes": metrics["wal_bytes"],
    }


def _default_backup_path(settings: Settings) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return settings.output_dir / "backups" / f"ai4sec-platform-{timestamp}.db"


def _connect_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0
