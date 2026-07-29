from __future__ import annotations

from pathlib import Path
import sqlite3

import pytest

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.maintenance import backup_database, restore_database, verify_database
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
