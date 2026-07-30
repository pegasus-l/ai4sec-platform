from __future__ import annotations

import calendar
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
from typing import Any

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.core.time import utc_now
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
    result = {
        "path": str(database_path),
        "database_bytes": _file_size(database_path),
        "wal_bytes": _file_size(Path(f"{database_path}-wal")),
        "shm_bytes": _file_size(Path(f"{database_path}-shm")),
        "journal_mode": str(conn.execute("PRAGMA journal_mode").fetchone()[0]),
        "synchronous": int(conn.execute("PRAGMA synchronous").fetchone()[0]),
        "busy_timeout_ms": int(conn.execute("PRAGMA busy_timeout").fetchone()[0]),
        "wal_autocheckpoint_pages": int(conn.execute("PRAGMA wal_autocheckpoint").fetchone()[0]),
        "page_size": page_size,
        "page_count": page_count,
        "freelist_count": freelist_count,
        "allocated_bytes": page_size * page_count,
        "free_bytes": page_size * freelist_count,
        "schema_version": current_schema_version(conn),
    }
    maintenance_table = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'database_maintenance_runs'"
    ).fetchone()
    if maintenance_table:
        maintenance = conn.execute(
            """
            SELECT COUNT(*) AS run_count,
                   COALESCE(SUM(lock_wait_ms), 0) AS lock_wait_ms_total,
                   COALESCE(MAX(lock_wait_ms), 0) AS lock_wait_ms_max,
                   COALESCE(SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END), 0) AS failure_count
            FROM database_maintenance_runs
            """
        ).fetchone()
        latest = conn.execute(
            "SELECT status, finished_at FROM database_maintenance_runs ORDER BY id DESC LIMIT 1"
        ).fetchone()
        result["maintenance"] = {
            "run_count": int(maintenance["run_count"]),
            "failure_count": int(maintenance["failure_count"]),
            "lock_wait_ms_total": int(maintenance["lock_wait_ms_total"]),
            "lock_wait_ms_max": int(maintenance["lock_wait_ms_max"]),
            "latest_status": str(latest["status"]) if latest else "never",
            "latest_finished_at": str(latest["finished_at"]) if latest else "",
        }
    return result


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
        wal_bytes_before = database_metrics(conn, cfg)["wal_bytes"]
        started = time.perf_counter()
        row = conn.execute(f"PRAGMA wal_checkpoint({checkpoint_mode})").fetchone()
        duration_ms = int((time.perf_counter() - started) * 1000)
        metrics = database_metrics(conn, cfg)
    return {
        "mode": checkpoint_mode,
        "busy": int(row[0]),
        "log_frames": int(row[1]),
        "checkpointed_frames": int(row[2]),
        "duration_ms": duration_ms,
        "wal_bytes_before": wal_bytes_before,
        "wal_bytes": metrics["wal_bytes"],
    }


def run_database_maintenance(
    *,
    checkpoint_mode: str = "PASSIVE",
    integrity_mode: str = "QUICK",
    lock_timeout_ms: int = 5_000,
    settings: Settings | None = None,
) -> dict[str, Any]:
    checkpoint_mode = checkpoint_mode.strip().upper()
    integrity_mode = integrity_mode.strip().upper()
    if checkpoint_mode not in {"PASSIVE", "FULL", "RESTART", "TRUNCATE"}:
        raise ValueError(f"Unsupported WAL checkpoint mode: {checkpoint_mode}")
    if integrity_mode not in {"QUICK", "FULL"}:
        raise ValueError(f"Unsupported integrity mode: {integrity_mode}")
    if lock_timeout_ms <= 0:
        raise ValueError("Maintenance lock timeout must be positive")

    cfg = settings or load_settings()
    started_at = utc_now()
    started = time.perf_counter()
    report: dict[str, Any] = {
        "status": "failed",
        "checkpoint_mode": checkpoint_mode,
        "integrity_mode": integrity_mode,
        "lock_timeout_ms": lock_timeout_ms,
        "lock_wait_ms": 0,
        "started_at": started_at,
    }
    maintenance_cfg = cfg.model_copy(
        update={"sqlite_busy_timeout_ms": min(cfg.sqlite_busy_timeout_ms, lock_timeout_ms)}
    )
    try:
        with _database_maintenance_lock(cfg.output_dir / "locks" / "database-maintenance.lock"):
            with connect(maintenance_cfg) as conn:
                metrics_before = database_metrics(conn, cfg)
                report["metrics_before"] = metrics_before
                lock_wait_ms = _measure_write_lock_wait(conn, timeout_ms=lock_timeout_ms)
                report["lock_wait_ms"] = lock_wait_ms

                integrity_started = time.perf_counter()
                pragma = "quick_check" if integrity_mode == "QUICK" else "integrity_check"
                integrity_rows = [str(row[0]) for row in conn.execute(f"PRAGMA {pragma}").fetchall()]
                integrity_duration_ms = int((time.perf_counter() - integrity_started) * 1000)
                report["integrity_duration_ms"] = integrity_duration_ms
                if integrity_rows != ["ok"]:
                    raise sqlite3.DatabaseError(f"SQLite {pragma} failed: {integrity_rows}")

                checkpoint_started = time.perf_counter()
                checkpoint_row = conn.execute(f"PRAGMA wal_checkpoint({checkpoint_mode})").fetchone()
                checkpoint_duration_ms = int((time.perf_counter() - checkpoint_started) * 1000)
                metrics_after = database_metrics(conn, cfg)
                checkpoint = {
                    "busy": int(checkpoint_row[0]),
                    "log_frames": int(checkpoint_row[1]),
                    "checkpointed_frames": int(checkpoint_row[2]),
                }
                report.update(
                    {
                        "status": "success" if checkpoint["busy"] == 0 else "partial",
                        "lock_wait_ms": lock_wait_ms,
                        "integrity": "ok",
                        "integrity_duration_ms": integrity_duration_ms,
                        "checkpoint": checkpoint,
                        "checkpoint_duration_ms": checkpoint_duration_ms,
                        "metrics_before": metrics_before,
                        "metrics_after": metrics_after,
                    }
                )
                finished_at = utc_now()
                conn.execute(
                    """
                    INSERT INTO database_maintenance_runs(
                        status, checkpoint_mode, integrity_mode, lock_wait_ms,
                        checkpoint_duration_ms, integrity_duration_ms,
                        wal_bytes_before, wal_bytes_after, details_json, started_at, finished_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        report["status"],
                        checkpoint_mode,
                        integrity_mode,
                        lock_wait_ms,
                        checkpoint_duration_ms,
                        integrity_duration_ms,
                        int(metrics_before["wal_bytes"]),
                        int(metrics_after["wal_bytes"]),
                        json.dumps({"checkpoint": checkpoint}, ensure_ascii=False, sort_keys=True),
                        started_at,
                        finished_at,
                    ),
                )
                conn.commit()
    except Exception as exc:
        report["error"] = str(exc)
        report["error_type"] = type(exc).__name__
        if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
            _record_failed_maintenance(maintenance_cfg, report)
    report["finished_at"] = utc_now()
    report["duration_ms"] = int((time.perf_counter() - started) * 1000)
    report_paths = _write_maintenance_report(cfg, report)
    report["report_path"] = str(report_paths[0])
    report["latest_report_path"] = str(report_paths[1])
    return report


def _measure_write_lock_wait(conn: sqlite3.Connection, *, timeout_ms: int) -> int:
    previous_timeout = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])
    started = time.perf_counter()
    transaction_started = False
    try:
        conn.execute(f"PRAGMA busy_timeout = {timeout_ms}")
        conn.execute("BEGIN IMMEDIATE")
        transaction_started = True
        conn.rollback()
        transaction_started = False
        return int((time.perf_counter() - started) * 1000)
    finally:
        if transaction_started:
            conn.rollback()
        conn.execute(f"PRAGMA busy_timeout = {previous_timeout}")


@contextmanager
def _database_maintenance_lock(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    handle = path.open("a+", encoding="utf-8")
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("another database maintenance task is already running") from exc
        yield
    finally:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        handle.close()


def _record_failed_maintenance(settings: Settings, report: dict[str, Any]) -> None:
    try:
        with connect(settings) as conn:
            table = conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'database_maintenance_runs'"
            ).fetchone()
            if not table:
                return
            metrics_before = report.get("metrics_before") or {}
            conn.execute(
                """
                INSERT INTO database_maintenance_runs(
                    status, checkpoint_mode, integrity_mode, lock_wait_ms,
                    checkpoint_duration_ms, integrity_duration_ms,
                    wal_bytes_before, wal_bytes_after, details_json, started_at, finished_at
                ) VALUES ('failed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report["checkpoint_mode"],
                    report["integrity_mode"],
                    int(report.get("lock_wait_ms") or 0),
                    int(report.get("checkpoint_duration_ms") or 0),
                    int(report.get("integrity_duration_ms") or 0),
                    int(metrics_before.get("wal_bytes") or 0),
                    int((report.get("metrics_after") or {}).get("wal_bytes") or 0),
                    json.dumps(
                        {"error": report.get("error", ""), "error_type": report.get("error_type", "")},
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                    report["started_at"],
                    utc_now(),
                ),
            )
            conn.commit()
    except (OSError, sqlite3.Error, RuntimeError):
        return


def _write_maintenance_report(settings: Settings, report: dict[str, Any]) -> tuple[Path, Path]:
    directory = settings.output_dir / "operations" / "database-maintenance"
    directory.mkdir(parents=True, exist_ok=True, mode=0o750)
    directory.chmod(0o750)
    _prune_maintenance_reports(directory, settings.database_maintenance_report_retention_days)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    history_path = directory / f"maintenance-{stamp}.json"
    latest_path = directory / "latest.json"
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    _write_json_atomic(history_path, payload)
    _write_json_atomic(latest_path, payload)
    return history_path, latest_path


def _prune_maintenance_reports(directory: Path, retention_days: int) -> None:
    cutoff = time.time() - retention_days * 24 * 60 * 60
    for path in directory.glob("maintenance-*.json"):
        try:
            if path.stat().st_mtime < cutoff:
                path.unlink()
        except FileNotFoundError:
            continue


def _write_json_atomic(path: Path, payload: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(payload, encoding="utf-8")
    os.chmod(temporary, 0o640)
    _sync_file(temporary)
    os.replace(temporary, path)
    _sync_directory(path.parent)


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
