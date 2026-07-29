from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import hashlib
import sqlite3

from ai4sec_platform.core.time import utc_now


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]
    checksum_source: str

    @property
    def checksum(self) -> str:
        return hashlib.sha256(self.checksum_source.encode("utf-8")).hexdigest()


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        name="add_domain_items_last_synced_at",
        apply=lambda conn: _add_column_if_missing(conn, "domain_items", "last_synced_at", "TEXT"),
        checksum_source="domain_items.last_synced_at TEXT",
    ),
    Migration(
        version=2,
        name="add_human_queue_items_queue_source",
        apply=lambda conn: _add_column_if_missing(conn, "human_queue_items", "queue_source", "TEXT NOT NULL DEFAULT 'pipeline'"),
        checksum_source="human_queue_items.queue_source TEXT NOT NULL DEFAULT 'pipeline'",
    ),
    Migration(
        version=3,
        name="add_pipeline_jobs_cancel_requested",
        apply=lambda conn: _add_column_if_missing(conn, "pipeline_jobs", "cancel_requested", "INTEGER NOT NULL DEFAULT 0"),
        checksum_source="pipeline_jobs.cancel_requested INTEGER NOT NULL DEFAULT 0",
    ),
)


def apply_migrations(conn: sqlite3.Connection, migrations: Sequence[Migration] = MIGRATIONS) -> None:
    _ensure_migration_table(conn)
    _validate_migration_sequence(migrations)
    applied = {
        int(row["version"] if isinstance(row, sqlite3.Row) else row[0]): row
        for row in conn.execute("SELECT version, name, checksum FROM schema_migrations ORDER BY version").fetchall()
    }
    for migration in migrations:
        existing = applied.get(migration.version)
        if existing:
            name = str(existing["name"] if isinstance(existing, sqlite3.Row) else existing[1])
            checksum = str(existing["checksum"] if isinstance(existing, sqlite3.Row) else existing[2])
            if name != migration.name or checksum != migration.checksum:
                raise RuntimeError(f"Migration history mismatch at version {migration.version}")
            continue
        try:
            conn.execute("BEGIN IMMEDIATE")
            migration.apply(conn)
            conn.execute(
                "INSERT INTO schema_migrations(version, name, checksum, applied_at) VALUES (?, ?, ?, ?)",
                (migration.version, migration.name, migration.checksum, utc_now()),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def current_schema_version(conn: sqlite3.Connection) -> int:
    _ensure_migration_table(conn)
    row = conn.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations").fetchone()
    return int(row[0])


def _ensure_migration_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TEXT NOT NULL
        )
        """
    )
    conn.commit()


def _validate_migration_sequence(migrations: Sequence[Migration]) -> None:
    versions = [migration.version for migration in migrations]
    if versions != sorted(versions) or len(versions) != len(set(versions)) or any(version <= 0 for version in versions):
        raise ValueError("Migration versions must be unique positive integers in ascending order")


def _add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    table_exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
    if not table_exists:
        raise RuntimeError(f"Migration target table does not exist: {table}")
    columns = {str(row[1]) for row in conn.execute(f'PRAGMA table_info("{table}")').fetchall()}
    if column not in columns:
        conn.execute(f'ALTER TABLE "{table}" ADD COLUMN "{column}" {definition}')
