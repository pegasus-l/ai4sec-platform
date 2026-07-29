from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.db.migrations import current_schema_version
from ai4sec_platform.db.session import connect


BACKUP_PREFIX = "ai4sec-platform-"
BACKUP_SUFFIX = ".db"


@dataclass(frozen=True)
class BackupRetentionPolicy:
    daily_days: int = 7
    weekly_weeks: int = 4
    monthly_months: int = 6

    def validate(self) -> None:
        if self.daily_days <= 0 or self.weekly_weeks <= 0 or self.monthly_months <= 0:
            raise ValueError("Backup retention values must be positive")


def backup_database(
    destination: Path | None = None,
    settings: Settings | None = None,
) -> Path:
    cfg = settings or load_settings()
    target = destination or _default_backup_path(cfg)
    target = target.expanduser().resolve()
    if target == cfg.database_path.expanduser().resolve():
        raise ValueError("Backup destination must differ from the active database")
    if target.exists():
        raise FileExistsError(f"Backup destination already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    temporary.unlink(missing_ok=True)
    target_created = False
    try:
        with connect(cfg) as source, sqlite3.connect(temporary) as backup:
            source.backup(backup)
        verify_database(temporary)
        _sync_file(temporary)
        try:
            os.link(temporary, target)
        except FileExistsError as exc:
            raise FileExistsError(f"Backup destination already exists: {target}") from exc
        target_created = True
        temporary.unlink()
        _write_backup_manifest(target, cfg)
        _sync_directory(target.parent)
    except Exception:
        temporary.unlink(missing_ok=True)
        if target_created:
            target.unlink(missing_ok=True)
            _manifest_path(target).unlink(missing_ok=True)
        raise
    return target


def restore_database(
    backup_path: Path,
    destination: Path,
    *,
    overwrite: bool = False,
    settings: Settings | None = None,
) -> Path:
    cfg = settings or load_settings()
    source_path = backup_path.expanduser().resolve()
    target = destination.expanduser().resolve()
    if source_path == target:
        raise ValueError("Backup and restore destination must differ")
    if target == cfg.database_path.expanduser().resolve():
        raise ValueError("Restore into the active database is forbidden; restore to a staging path and swap it offline")
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
        _sync_file(temporary)
        if overwrite:
            Path(f"{target}-wal").unlink(missing_ok=True)
            Path(f"{target}-shm").unlink(missing_ok=True)
        os.replace(temporary, target)
        _sync_directory(target.parent)
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
        schema_version = _read_schema_version(conn)
    result = {
        "path": str(database_path),
        "integrity": "ok",
        "table_count": table_count,
        "schema_version": schema_version,
        "bytes": database_path.stat().st_size,
        "sha256": _sha256_file(database_path),
        "manifest": "absent",
    }
    manifest_path = _manifest_path(database_path)
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        _verify_backup_manifest(database_path, result, manifest)
        result["manifest"] = "verified"
    return result


def prune_database_backups(
    directory: Path,
    policy: BackupRetentionPolicy | None = None,
    *,
    now: datetime | None = None,
) -> list[Path]:
    retention = policy or BackupRetentionPolicy()
    retention.validate()
    backup_dir = directory.expanduser().resolve()
    if not backup_dir.is_dir():
        return []
    backups = sorted(
        (
            path
            for path in backup_dir.glob(f"{BACKUP_PREFIX}*{BACKUP_SUFFIX}")
            if path.is_file()
        ),
        key=_backup_created_at,
        reverse=True,
    )
    current_time = now or datetime.now(timezone.utc)
    daily_cutoff = current_time - timedelta(days=retention.daily_days)
    weekly_cutoff = current_time - timedelta(weeks=retention.weekly_weeks)
    monthly_cutoff = _subtract_months(current_time, retention.monthly_months)
    weekly_buckets: set[tuple[int, int]] = set()
    monthly_buckets: set[tuple[int, int]] = set()
    removed: list[Path] = []
    for path in backups[1:]:
        modified_at = _backup_created_at(path)
        if modified_at >= daily_cutoff:
            continue
        if modified_at >= weekly_cutoff:
            week = modified_at.isocalendar()
            bucket = (week.year, week.week)
            if bucket not in weekly_buckets:
                weekly_buckets.add(bucket)
                continue
        elif modified_at >= monthly_cutoff:
            bucket = (modified_at.year, modified_at.month)
            if bucket not in monthly_buckets:
                monthly_buckets.add(bucket)
                continue
        path.unlink()
        _manifest_path(path).unlink(missing_ok=True)
        removed.append(path)
    return removed


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
    return settings.output_dir / "backups" / f"{BACKUP_PREFIX}{timestamp}{BACKUP_SUFFIX}"


def _connect_read_only(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)


def _file_size(path: Path) -> int:
    try:
        return path.stat().st_size
    except FileNotFoundError:
        return 0


def _read_schema_version(conn: sqlite3.Connection) -> int:
    migration_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_migrations'"
    ).fetchone()
    if migration_table is None:
        return 0
    row = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()
    return int(row[0])


def _subtract_months(value: datetime, months: int) -> datetime:
    month_index = value.year * 12 + value.month - 1 - months
    year, zero_based_month = divmod(month_index, 12)
    month = zero_based_month + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def _manifest_path(database_path: Path) -> Path:
    return database_path.with_name(f"{database_path.name}.manifest.json")


def _write_backup_manifest(database_path: Path, settings: Settings) -> None:
    verification = verify_database(database_path)
    manifest = {
        "format_version": 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "backup_file": database_path.name,
        "source_database": settings.database_path.name,
        "bytes": verification["bytes"],
        "sha256": verification["sha256"],
        "schema_version": verification["schema_version"],
    }
    manifest_path = _manifest_path(database_path)
    temporary = manifest_path.with_name(f".{manifest_path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        _sync_file(temporary)
        os.replace(temporary, manifest_path)
    finally:
        temporary.unlink(missing_ok=True)


def _verify_backup_manifest(database_path: Path, verification: dict[str, Any], manifest: dict[str, Any]) -> None:
    expected = {
        "format_version": 1,
        "backup_file": database_path.name,
        "bytes": verification["bytes"],
        "sha256": verification["sha256"],
        "schema_version": verification["schema_version"],
    }
    mismatches = [key for key, value in expected.items() if manifest.get(key) != value]
    if mismatches:
        raise ValueError(f"Backup manifest mismatch: {', '.join(mismatches)}")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _backup_created_at(path: Path) -> datetime:
    timestamp = path.name.removeprefix(BACKUP_PREFIX).removesuffix(BACKUP_SUFFIX)
    try:
        return datetime.strptime(timestamp, "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)


def _sync_file(path: Path) -> None:
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError as exc:
        if exc.errno in {errno.EINVAL, errno.ENOTSUP, errno.EACCES}:
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno not in {errno.EINVAL, errno.ENOTSUP}:
                raise
    finally:
        os.close(descriptor)
