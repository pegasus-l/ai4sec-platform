from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest
from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import app
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.maintenance import backup_database, checkpoint_wal, database_metrics, restore_database, verify_database
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


def test_invalid_sqlite_settings_fall_back_to_safe_defaults(monkeypatch) -> None:
    monkeypatch.setenv("AI4SEC_SQLITE_BUSY_TIMEOUT_MS", "invalid")
    monkeypatch.setenv("AI4SEC_SQLITE_SYNCHRONOUS", "invalid")

    settings = load_settings()

    assert settings.sqlite_busy_timeout_ms == 30_000
    assert settings.sqlite_synchronous == "NORMAL"


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
    with sqlite3.connect(restored_path) as restored:
        count = restored.execute("SELECT COUNT(*) FROM data_sources WHERE name = ?", ("backup-source",)).fetchone()[0]
    assert count == 1


def test_restore_refuses_existing_destination_without_overwrite(tmp_path: Path) -> None:
    backup_path = backup_database(tmp_path / "backup.db")
    destination = tmp_path / "existing.db"
    destination.touch()

    with pytest.raises(FileExistsError):
        restore_database(backup_path, destination)


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

    apply_migrations(conn)

    assert current_schema_version(conn) == 4
    assert {row[1] for row in conn.execute("PRAGMA table_info(domain_items)")} >= {"last_synced_at"}
    assert {row[1] for row in conn.execute("PRAGMA table_info(human_queue_items)")} >= {"queue_source"}
    assert {row[1] for row in conn.execute("PRAGMA table_info(pipeline_jobs)")} >= {"cancel_requested"}
    assert {row[1] for row in conn.execute("PRAGMA table_info(capability_repro_tasks)")} >= {
        "started_at", "updated_at", "worker_id", "heartbeat_at", "cancel_requested", "cleanup_requested"
    }
    assert conn.execute("SELECT title FROM domain_items WHERE id = 1").fetchone()[0] == "legacy item"
    conn.close()


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
    assert metrics["schema_version"] == 4
    assert metrics["database_bytes"] > 0
    assert metrics["allocated_bytes"] >= metrics["database_bytes"]


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
    assert payload["database"]["schema_version"] == 4
