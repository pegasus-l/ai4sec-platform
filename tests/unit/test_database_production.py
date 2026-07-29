from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import stat

import pytest
from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import app
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.maintenance import BackupRetentionPolicy, backup_database, checkpoint_wal, database_metrics, database_write_probe, prune_database_backups, restore_database, verify_database
from ai4sec_platform.db.migrations import MIGRATIONS, Migration, apply_migrations, current_schema_version
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect


def test_connection_enables_production_sqlite_pragmas(monkeypatch) -> None:
    monkeypatch.setenv("AI4SEC_SQLITE_BUSY_TIMEOUT_MS", "4321")
    monkeypatch.setenv("AI4SEC_SQLITE_SYNCHRONOUS", "FULL")

    with connect() as conn:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == 4321
        assert conn.execute("PRAGMA synchronous").fetchone()[0] == 2


def test_connection_enforces_private_database_permissions(tmp_path: Path) -> None:
    database_path = tmp_path / "sqlite" / "platform.db"
    settings = load_settings().model_copy(
        update={"project_root": tmp_path, "output_dir": tmp_path / "output", "database_path": database_path}
    )

    with connect(settings) as conn:
        conn.execute("CREATE TABLE permission_probe(id INTEGER PRIMARY KEY)")
        conn.commit()

    assert stat.S_IMODE(database_path.parent.stat().st_mode) == 0o750
    assert stat.S_IMODE(database_path.stat().st_mode) == 0o640


def test_connection_fails_when_database_permissions_cannot_be_enforced(monkeypatch, tmp_path: Path) -> None:
    database_path = tmp_path / "sqlite" / "platform.db"
    settings = load_settings().model_copy(
        update={"project_root": tmp_path, "output_dir": tmp_path / "output", "database_path": database_path}
    )
    original_chmod = os.chmod

    def reject_database_chmod(path, mode):
        if Path(path) == database_path:
            raise PermissionError("operation not permitted")
        return original_chmod(path, mode)

    monkeypatch.setattr(os, "chmod", reject_database_chmod)

    with pytest.raises(RuntimeError, match="Cannot enforce SQLite file permissions"):
        connect(settings)


def test_invalid_sqlite_settings_fall_back_to_safe_defaults(monkeypatch) -> None:
    monkeypatch.setenv("AI4SEC_SQLITE_BUSY_TIMEOUT_MS", "invalid")
    monkeypatch.setenv("AI4SEC_SQLITE_SYNCHRONOUS", "invalid")

    settings = load_settings()

    assert settings.sqlite_busy_timeout_ms == 30_000
    assert settings.sqlite_synchronous == "NORMAL"
    assert settings.backup_daily_retention_days == 7
    assert settings.backup_weekly_retention_weeks == 4
    assert settings.backup_monthly_retention_months == 6
    assert settings.pipeline_worker_heartbeat_seconds == 10
    assert settings.pipeline_job_lease_seconds == 45


def test_request_database_dependency_rolls_back_on_error() -> None:
    dependency = get_db()
    conn = next(dependency)
    conn.execute(
        "INSERT INTO data_sources(domain, name, source_type, status, summary_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("news", "rollback-source", "test", "shadow", "{}", "2026-07-28T00:00:00Z"),
    )

    with pytest.raises(RuntimeError, match="request failed"):
        dependency.throw(RuntimeError("request failed"))

    with connect() as check_conn:
        init_db(check_conn)
        count = check_conn.execute("SELECT COUNT(*) FROM data_sources WHERE name = ?", ("rollback-source",)).fetchone()[0]
    assert count == 0


def test_online_backup_and_restore_include_committed_wal_data(tmp_path: Path) -> None:
    with connect() as conn:
        init_db(conn)
        conn.execute(
            "INSERT INTO data_sources(domain, name, source_type, status, summary_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            ("news", "backup-source", "test", "shadow", "{}", "2026-07-28T00:00:00Z"),
        )
        conn.commit()

    backup_path = backup_database(tmp_path / "backups" / "platform.db")
    backup_result = verify_database(backup_path)
    restored_path = restore_database(backup_path, tmp_path / "restored" / "platform.db")

    assert backup_result["integrity"] == "ok"
    assert backup_result["table_count"] > 0
    assert backup_result["manifest"] == "verified"
    assert backup_result["sha256"]
    assert backup_path.with_name(f"{backup_path.name}.manifest.json").is_file()
    with sqlite3.connect(restored_path) as restored:
        count = restored.execute("SELECT COUNT(*) FROM data_sources WHERE name = ?", ("backup-source",)).fetchone()[0]
    assert count == 1


def test_restore_refuses_existing_destination_without_overwrite(tmp_path: Path) -> None:
    backup_path = backup_database(tmp_path / "backup.db")
    destination = tmp_path / "existing.db"
    destination.touch()

    with pytest.raises(FileExistsError):
        restore_database(backup_path, destination)


def test_backup_refuses_to_replace_existing_file(tmp_path: Path) -> None:
    destination = tmp_path / "backup.db"
    destination.write_text("keep-me", encoding="utf-8")

    with pytest.raises(FileExistsError):
        backup_database(destination)

    assert destination.read_text(encoding="utf-8") == "keep-me"


def test_verify_rejects_mismatched_backup_manifest(tmp_path: Path) -> None:
    with connect() as conn:
        init_db(conn)
    backup_path = backup_database(tmp_path / "backup.db")
    manifest_path = backup_path.with_name(f"{backup_path.name}.manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="sha256"):
        verify_database(backup_path)


def test_restore_refuses_active_database_destination(tmp_path: Path) -> None:
    with connect() as conn:
        init_db(conn)
    backup_path = backup_database(tmp_path / "backup.db")
    active_database = load_settings().database_path

    with pytest.raises(ValueError, match="active database"):
        restore_database(backup_path, active_database, overwrite=True)


def test_backup_retention_removes_old_managed_sets_but_keeps_latest(tmp_path: Path) -> None:
    now = datetime(2026, 7, 29, tzinfo=timezone.utc)
    old_backup = tmp_path / "ai4sec-platform-20251201T000000000000Z.db"
    latest_backup = tmp_path / "ai4sec-platform-20260729T000000000000Z.db"
    unrelated = tmp_path / "manual-copy.db"
    for path in (old_backup, latest_backup, unrelated):
        path.write_text("placeholder", encoding="utf-8")
    old_manifest = old_backup.with_name(f"{old_backup.name}.manifest.json")
    old_manifest.write_text("{}", encoding="utf-8")
    old_timestamp = (now - timedelta(days=240)).timestamp()
    os.utime(old_backup, (old_timestamp, old_timestamp))

    removed = prune_database_backups(tmp_path, BackupRetentionPolicy(), now=now)

    assert removed == [old_backup]
    assert not old_backup.exists()
    assert not old_manifest.exists()
    assert latest_backup.exists()
    assert unrelated.exists()


def test_backup_retention_keeps_one_weekly_and_monthly_backup(tmp_path: Path) -> None:
    now = datetime(2026, 7, 29, tzinfo=timezone.utc)
    ages = {
        "ai4sec-platform-latest.db": 0,
        "ai4sec-platform-daily.db": 1,
        "ai4sec-platform-weekly-new.db": 10,
        "ai4sec-platform-weekly-old.db": 11,
        "ai4sec-platform-monthly-new.db": 50,
        "ai4sec-platform-monthly-old.db": 55,
    }
    backups: dict[str, Path] = {}
    for name, age_days in ages.items():
        path = tmp_path / name
        path.write_text("placeholder", encoding="utf-8")
        timestamp = (now - timedelta(days=age_days)).timestamp()
        os.utime(path, (timestamp, timestamp))
        backups[name] = path

    removed = prune_database_backups(tmp_path, BackupRetentionPolicy(), now=now)

    assert set(removed) == {
        backups["ai4sec-platform-weekly-old.db"],
        backups["ai4sec-platform-monthly-old.db"],
    }
    assert backups["ai4sec-platform-latest.db"].exists()
    assert backups["ai4sec-platform-daily.db"].exists()
    assert backups["ai4sec-platform-weekly-new.db"].exists()
    assert backups["ai4sec-platform-monthly-new.db"].exists()


def test_verify_rejects_non_database_file(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.db"
    invalid.write_text("not sqlite", encoding="utf-8")

    with pytest.raises(sqlite3.DatabaseError):
        verify_database(invalid)


def test_new_database_records_all_schema_migrations() -> None:
    with connect() as conn:
        init_db(conn)
        rows = conn.execute("SELECT version, name FROM schema_migrations ORDER BY version").fetchall()

    assert [(row["version"], row["name"]) for row in rows] == [(migration.version, migration.name) for migration in MIGRATIONS]


def test_legacy_database_is_upgraded_without_losing_rows(tmp_path: Path) -> None:
    database_path = tmp_path / "legacy.db"
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(
        """
        CREATE TABLE domain_items (
            id INTEGER PRIMARY KEY, domain TEXT NOT NULL, item_type TEXT NOT NULL, title TEXT NOT NULL,
            summary TEXT NOT NULL DEFAULT '', score REAL, status TEXT NOT NULL DEFAULT 'active',
            source TEXT NOT NULL DEFAULT '', source_url TEXT NOT NULL DEFAULT '', primary_date TEXT NOT NULL DEFAULT '',
            tags_json TEXT NOT NULL DEFAULT '[]', metrics_json TEXT NOT NULL DEFAULT '{}', payload_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE human_queue_items (
            id INTEGER PRIMARY KEY, domain TEXT NOT NULL, item_id INTEGER, queue_type TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending', priority INTEGER NOT NULL DEFAULT 3, reason TEXT NOT NULL DEFAULT '',
            assignee TEXT NOT NULL DEFAULT '', payload_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE pipeline_jobs (
            id INTEGER PRIMARY KEY, run_id TEXT NOT NULL UNIQUE, domain TEXT NOT NULL, pipeline_name TEXT NOT NULL,
            params_json TEXT NOT NULL DEFAULT '{}', reset_requested INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'queued',
            attempt_count INTEGER NOT NULL DEFAULT 0, worker_id TEXT NOT NULL DEFAULT '', heartbeat_at TEXT NOT NULL DEFAULT '',
            error_message TEXT NOT NULL DEFAULT '', queued_at TEXT NOT NULL, started_at TEXT NOT NULL DEFAULT '',
            finished_at TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
        );
        CREATE TABLE capability_repro_tasks (
            id INTEGER PRIMARY KEY, item_id INTEGER NOT NULL, repo_url TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued', container_name TEXT NOT NULL DEFAULT '',
            workspace_path TEXT NOT NULL DEFAULT '', log TEXT NOT NULL DEFAULT '', result TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL, finished_at TEXT NOT NULL DEFAULT '', cleaned_at TEXT NOT NULL DEFAULT '',
            trigger TEXT NOT NULL DEFAULT 'manual', report_json TEXT NOT NULL DEFAULT '{}',
            web_port INTEGER, web_url TEXT NOT NULL DEFAULT ''
        );
        INSERT INTO domain_items(id, domain, item_type, title, created_at, updated_at)
        VALUES (1, 'news', 'article', 'legacy item', '2026-07-28T00:00:00Z', '2026-07-28T00:00:00Z');
        """
    )
    conn.commit()

    init_db(conn)

    assert current_schema_version(conn) == MIGRATIONS[-1].version
    assert {row[1] for row in conn.execute("PRAGMA table_info(domain_items)")} >= {"last_synced_at"}
    assert {row[1] for row in conn.execute("PRAGMA table_info(human_queue_items)")} >= {"queue_source"}
    assert {row[1] for row in conn.execute("PRAGMA table_info(pipeline_jobs)")} >= {"cancel_requested"}
    assert {row[1] for row in conn.execute("PRAGMA table_info(pipeline_jobs)")} >= {"lease_expires_at"}
    assert conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_workers'").fetchone()
    assert {row[1] for row in conn.execute("PRAGMA table_info(capability_repro_tasks)")} >= {
        "started_at", "updated_at", "worker_id", "heartbeat_at", "cancel_requested", "cleanup_requested"
    }
    assert conn.execute("SELECT title FROM domain_items WHERE id = 1").fetchone()[0] == "legacy item"
    conn.close()


def test_platform_identity_migration_deduplicates_legacy_rows() -> None:
    with connect() as conn:
        init_db(conn)
        for index_name in ("uq_task_runs_run_step", "uq_artifacts_run_path", "uq_data_sources_domain_name"):
            conn.execute(f'DROP INDEX "{index_name}"')
        conn.execute("DELETE FROM schema_migrations WHERE version = 5")
        repo.create_pipeline_run(conn, run_id="legacy-duplicates", domain="news", pipeline_name="test.pipeline")
        conn.execute(
            "INSERT INTO task_runs(run_id, step_name, status, metrics_json) VALUES (?, ?, 'failed', '{}'), (?, ?, 'success', '{}')",
            ("legacy-duplicates", "collect", "legacy-duplicates", "collect"),
        )
        conn.execute(
            "INSERT INTO artifacts(run_id, artifact_type, path, sha256, bytes, payload_summary_json, created_at) VALUES (?, 'raw', ?, 'old', 1, '{}', 'old'), (?, 'raw', ?, 'new', 2, '{}', 'new')",
            ("legacy-duplicates", "/tmp/artifact.json", "legacy-duplicates", "/tmp/artifact.json"),
        )
        conn.execute(
            "INSERT INTO data_sources(domain, name, source_type, status, summary_json, created_at) VALUES ('news', 'arxiv', 'api', 'failed', '{}', 'old'), ('news', 'arxiv', 'api', 'success', '{}', 'new')"
        )
        conn.commit()

        apply_migrations(conn)

        assert conn.execute("SELECT status FROM task_runs WHERE run_id = 'legacy-duplicates'").fetchall()[0][0] == "success"
        assert conn.execute("SELECT sha256 FROM artifacts WHERE run_id = 'legacy-duplicates'").fetchall()[0][0] == "new"
        assert conn.execute("SELECT status FROM data_sources WHERE domain = 'news' AND name = 'arxiv'").fetchall()[0][0] == "success"
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO task_runs(run_id, step_name, status) VALUES ('legacy-duplicates', 'collect', 'failed')")


def test_platform_repository_identity_writes_are_idempotent() -> None:
    with connect() as conn:
        init_db(conn)
        repo.create_pipeline_run(conn, run_id="idempotent-run", domain="news", pipeline_name="test.pipeline")
        repo.create_task_run(conn, run_id="idempotent-run", step_name="collect", status="failed", metrics={"items": 1})
        repo.create_task_run(conn, run_id="idempotent-run", step_name="collect", status="success", metrics={"items": 2})
        repo.create_artifact(conn, run_id="idempotent-run", artifact_type="raw", path="/tmp/item.json", sha256="old")
        repo.create_artifact(conn, run_id="idempotent-run", artifact_type="raw", path="/tmp/item.json", sha256="new")
        repo.create_data_source(conn, domain="news", name="arxiv", source_type="api", status="failed")
        repo.create_data_source(conn, domain="news", name="arxiv", source_type="api", status="success")
        conn.commit()

        task = conn.execute("SELECT status, metrics_json FROM task_runs WHERE run_id = 'idempotent-run'").fetchall()
        artifact = conn.execute("SELECT sha256 FROM artifacts WHERE run_id = 'idempotent-run'").fetchall()
        source = conn.execute("SELECT status FROM data_sources WHERE domain = 'news' AND name = 'arxiv'").fetchall()

    assert len(task) == 1 and task[0]["status"] == "success" and json.loads(task[0]["metrics_json"])["items"] == 2
    assert len(artifact) == 1 and artifact[0]["sha256"] == "new"
    assert len(source) == 1 and source[0]["status"] == "success"


def test_migrations_are_idempotent_and_detect_history_mismatch() -> None:
    with connect() as conn:
        init_db(conn)
        apply_migrations(conn)
        assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == len(MIGRATIONS)
        conn.execute("UPDATE schema_migrations SET checksum = 'tampered' WHERE version = 1")
        conn.commit()

        with pytest.raises(RuntimeError, match="history mismatch"):
            apply_migrations(conn)


def test_failed_migration_rolls_back_schema_and_version_record(tmp_path: Path) -> None:
    conn = sqlite3.connect(tmp_path / "failure.db")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE sample(id INTEGER PRIMARY KEY)")
    migration = Migration(
        version=10,
        name="failing_migration",
        checksum_source="sample.failed",
        apply=lambda connection: _apply_failing_migration(connection),
    )

    with pytest.raises(RuntimeError, match="planned migration failure"):
        apply_migrations(conn, (migration,))

    assert "temporary_column" not in {row[1] for row in conn.execute("PRAGMA table_info(sample)")}
    assert conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0] == 0
    conn.close()


def _apply_failing_migration(conn: sqlite3.Connection) -> None:
    conn.execute("ALTER TABLE sample ADD COLUMN temporary_column TEXT")
    raise RuntimeError("planned migration failure")


def test_database_metrics_expose_wal_and_schema_state() -> None:
    settings = load_settings()
    with connect(settings) as conn:
        init_db(conn)
        metrics = database_metrics(conn, settings)

    assert metrics["path"] == str(settings.database_path.resolve())
    assert metrics["journal_mode"] == "wal"
    assert metrics["busy_timeout_ms"] == 30_000
    assert metrics["schema_version"] == MIGRATIONS[-1].version
    assert metrics["database_bytes"] > 0
    assert metrics["allocated_bytes"] >= metrics["database_bytes"]


def test_database_write_probe_rolls_back_without_residue() -> None:
    with connect() as conn:
        init_db(conn)
        previous_timeout = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])
        result = database_write_probe(conn, timeout_ms=100)
        residue = conn.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = -1").fetchone()[0]
        restored_timeout = int(conn.execute("PRAGMA busy_timeout").fetchone()[0])

    assert result["writable"] is True
    assert result["timeout_ms"] == 100
    assert residue == 0
    assert restored_timeout == previous_timeout


def test_wal_checkpoint_supports_controlled_modes() -> None:
    with connect() as conn:
        init_db(conn)
        conn.execute(
            "INSERT INTO data_sources(domain, name, source_type, created_at) VALUES (?, ?, ?, ?)",
            ("news", "checkpoint-source", "test", "2026-07-28T00:00:00Z"),
        )
        conn.commit()

    passive = checkpoint_wal("passive")
    truncated = checkpoint_wal("truncate")

    assert passive["mode"] == "PASSIVE"
    assert passive["busy"] == 0
    assert truncated["mode"] == "TRUNCATE"
    assert truncated["busy"] == 0
    assert truncated["wal_bytes"] == 0


def test_wal_checkpoint_rejects_unknown_mode() -> None:
    with pytest.raises(ValueError, match="Unsupported WAL checkpoint mode"):
        checkpoint_wal("unsafe")


def test_readiness_reports_database_metrics() -> None:
    response = TestClient(app).get("/api/health/ready")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["database"]["journal_mode"] == "wal"
    assert payload["database"]["schema_version"] == MIGRATIONS[-1].version
    assert payload["database"]["write_probe"]["writable"] is True


def test_readiness_returns_503_when_database_write_lock_is_held(tmp_path: Path) -> None:
    from ai4sec_platform.app.main import create_app
    from ai4sec_platform.core.config import Settings

    settings = Settings(
        project_root=tmp_path,
        output_dir=tmp_path / "output",
        database_path=tmp_path / "locked.db",
        readiness_write_timeout_ms=50,
    )
    with connect(settings) as setup:
        init_db(setup)
    lock = connect(settings)
    try:
        lock.execute("BEGIN IMMEDIATE")
        response = TestClient(create_app(settings)).get("/api/health/ready")
    finally:
        lock.rollback()
        lock.close()

    assert response.status_code == 503
    assert response.json()["status"] == "not_ready"
    assert response.json()["database"] == {"writable": False, "error": "database_locked"}
