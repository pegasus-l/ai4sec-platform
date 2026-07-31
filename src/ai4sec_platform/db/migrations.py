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
    Migration(
        version=4,
        name="add_capability_repro_worker_fields",
        apply=lambda conn: _add_repro_worker_fields(conn),
        checksum_source=(
            "capability_repro_tasks.started_at TEXT NOT NULL DEFAULT '';"
            "updated_at TEXT NOT NULL DEFAULT '';worker_id TEXT NOT NULL DEFAULT '';"
            "heartbeat_at TEXT NOT NULL DEFAULT '';cancel_requested INTEGER NOT NULL DEFAULT 0;"
            "cleanup_requested INTEGER NOT NULL DEFAULT 0"
        ),
    ),
    Migration(
        version=5,
        name="add_platform_identity_constraints",
        apply=lambda conn: _add_platform_identity_constraints(conn),
        checksum_source=(
            "dedupe task_runs(run_id,step_name), artifacts(run_id,path), data_sources(domain,name);"
            "unique indexes uq_task_runs_run_step,uq_artifacts_run_path,uq_data_sources_domain_name;"
            "query indexes pipeline_runs(domain,id),pipeline_runs(pipeline_name,status,id),"
            "quality_audits(domain,audit_type,id),human_queue_items(status,priority,id)"
        ),
    ),
    Migration(
        version=6,
        name="add_pipeline_worker_leases",
        apply=lambda conn: _add_pipeline_worker_leases(conn),
        checksum_source=(
            "pipeline_jobs.lease_expires_at TEXT NOT NULL DEFAULT '';"
            "pipeline_workers(worker_id,status,hostname,pid,started_at,heartbeat_at,stopped_at,current_run_id,metadata_json,updated_at);"
            "indexes pipeline_jobs(status,lease_expires_at),pipeline_workers(status,heartbeat_at)"
        ),
    ),
    Migration(
        version=7,
        name="add_platform_execution_controls",
        apply=lambda conn: _add_platform_execution_controls(conn),
        checksum_source="platform_controls(control_key primary key,enabled,reason,updated_at);pipeline_execution_kill_switch",
    ),
    Migration(
        version=8,
        name="add_database_maintenance_history",
        apply=lambda conn: _add_database_maintenance_history(conn),
        checksum_source=(
            "database_maintenance_runs(status,checkpoint_mode,integrity_mode,lock_wait_ms,"
            "checkpoint_duration_ms,integrity_duration_ms,wal_bytes_before,wal_bytes_after,"
            "details_json,started_at,finished_at);indexes recent,status"
        ),
    ),
    Migration(
        version=9,
        name="add_source_health_history",
        apply=lambda conn: _add_source_health_history(conn),
        checksum_source=(
            "source_health_checks(domain,source,status,message,latency_ms,consecutive_failures,"
            "last_success_at,details_json,checked_at);indexes source_recent,status_recent"
        ),
    ),
    Migration(
        version=10,
        name="add_source_incremental_state",
        apply=lambda conn: _add_source_incremental_state(conn),
        checksum_source=(
            "source_incremental_states(domain,source,state_key,state_json,updated_at);"
            "unique domain/source/state_key;index domain/source"
        ),
    ),
    Migration(
        version=11,
        name="add_model_call_idempotency",
        apply=lambda conn: _add_model_call_idempotency(conn),
        checksum_source=(
            "model_calls.request_key TEXT NOT NULL DEFAULT '';"
            "prompt_version TEXT NOT NULL DEFAULT '';attempt_no INTEGER NOT NULL DEFAULT 1;"
            "unique successful request_key;index request_key,status"
        ),
    ),
    Migration(
        version=12,
        name="add_human_queue_deduplication",
        apply=lambda conn: _add_human_queue_deduplication(conn),
        checksum_source=(
            "human_queue_items.dedupe_key TEXT NOT NULL DEFAULT '';"
            "unique pending domain/queue_type/dedupe_key;index domain/status/type"
        ),
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


def _add_repro_worker_fields(conn: sqlite3.Connection) -> None:
    for column, definition in (
        ("started_at", "TEXT NOT NULL DEFAULT ''"),
        ("updated_at", "TEXT NOT NULL DEFAULT ''"),
        ("worker_id", "TEXT NOT NULL DEFAULT ''"),
        ("heartbeat_at", "TEXT NOT NULL DEFAULT ''"),
        ("cancel_requested", "INTEGER NOT NULL DEFAULT 0"),
        ("cleanup_requested", "INTEGER NOT NULL DEFAULT 0"),
    ):
        _add_column_if_missing(conn, "capability_repro_tasks", column, definition)


def _add_platform_identity_constraints(conn: sqlite3.Connection) -> None:
    for table in ("task_runs", "artifacts", "data_sources", "pipeline_runs", "quality_audits", "human_queue_items"):
        exists = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
        if not exists:
            raise RuntimeError(f"Migration target table does not exist: {table}")
    conn.execute(
        "DELETE FROM task_runs WHERE id NOT IN (SELECT MAX(id) FROM task_runs GROUP BY run_id, step_name)"
    )
    conn.execute(
        "DELETE FROM artifacts WHERE id NOT IN (SELECT MAX(id) FROM artifacts GROUP BY run_id, path)"
    )
    conn.execute(
        "DELETE FROM data_sources WHERE id NOT IN (SELECT MAX(id) FROM data_sources GROUP BY domain, name)"
    )
    for statement in (
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_task_runs_run_step ON task_runs(run_id, step_name)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_artifacts_run_path ON artifacts(run_id, path)",
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_data_sources_domain_name ON data_sources(domain, name)",
        "CREATE INDEX IF NOT EXISTS idx_pipeline_runs_domain_recent ON pipeline_runs(domain, id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_pipeline_runs_pipeline_status ON pipeline_runs(pipeline_name, status, id)",
        "CREATE INDEX IF NOT EXISTS idx_quality_audits_domain_type_recent ON quality_audits(domain, audit_type, id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_human_queue_status_priority ON human_queue_items(status, priority, id)",
    ):
        conn.execute(statement)


def _add_pipeline_worker_leases(conn: sqlite3.Connection) -> None:
    _add_column_if_missing(conn, "pipeline_jobs", "lease_expires_at", "TEXT NOT NULL DEFAULT ''")
    conn.execute(
        """
        UPDATE pipeline_jobs
        SET lease_expires_at = CASE
            WHEN heartbeat_at != '' THEN heartbeat_at
            WHEN updated_at != '' THEN updated_at
            ELSE queued_at
        END
        WHERE status = 'running' AND lease_expires_at = ''
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS pipeline_workers (
            worker_id TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'running',
            hostname TEXT NOT NULL DEFAULT '',
            pid INTEGER NOT NULL DEFAULT 0,
            started_at TEXT NOT NULL,
            heartbeat_at TEXT NOT NULL,
            stopped_at TEXT NOT NULL DEFAULT '',
            current_run_id TEXT NOT NULL DEFAULT '',
            metadata_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_jobs_lease ON pipeline_jobs(status, lease_expires_at)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_pipeline_workers_status_heartbeat ON pipeline_workers(status, heartbeat_at)"
    )


def _add_platform_execution_controls(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS platform_controls (
            control_key TEXT PRIMARY KEY,
            enabled INTEGER NOT NULL DEFAULT 0,
            reason TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        )
        """
    )


def _add_database_maintenance_history(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS database_maintenance_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            status TEXT NOT NULL,
            checkpoint_mode TEXT NOT NULL,
            integrity_mode TEXT NOT NULL,
            lock_wait_ms INTEGER NOT NULL DEFAULT 0,
            checkpoint_duration_ms INTEGER NOT NULL DEFAULT 0,
            integrity_duration_ms INTEGER NOT NULL DEFAULT 0,
            wal_bytes_before INTEGER NOT NULL DEFAULT 0,
            wal_bytes_after INTEGER NOT NULL DEFAULT 0,
            details_json TEXT NOT NULL DEFAULT '{}',
            started_at TEXT NOT NULL,
            finished_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_database_maintenance_recent ON database_maintenance_runs(id DESC)")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_database_maintenance_status ON database_maintenance_runs(status, id DESC)"
    )


def _add_source_health_history(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS source_health_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            source TEXT NOT NULL,
            status TEXT NOT NULL,
            message TEXT NOT NULL DEFAULT '',
            latency_ms INTEGER NOT NULL DEFAULT 0,
            consecutive_failures INTEGER NOT NULL DEFAULT 0,
            last_success_at TEXT NOT NULL DEFAULT '',
            details_json TEXT NOT NULL DEFAULT '{}',
            checked_at TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source_health_source_recent ON source_health_checks(domain, source, id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source_health_status_recent ON source_health_checks(status, id DESC)")


def _add_source_incremental_state(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS source_incremental_states (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            source TEXT NOT NULL,
            state_key TEXT NOT NULL DEFAULT 'default',
            state_json TEXT NOT NULL DEFAULT '{}',
            updated_at TEXT NOT NULL,
            UNIQUE(domain, source, state_key)
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_source_incremental_domain_source ON source_incremental_states(domain, source)")


def _add_model_call_idempotency(conn: sqlite3.Connection) -> None:
    _add_column_if_missing(conn, "model_calls", "request_key", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "model_calls", "prompt_version", "TEXT NOT NULL DEFAULT ''")
    _add_column_if_missing(conn, "model_calls", "attempt_no", "INTEGER NOT NULL DEFAULT 1")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_model_calls_request_status ON model_calls(request_key, status)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_model_calls_success_request "
        "ON model_calls(request_key) WHERE request_key <> '' AND status = 'success'"
    )


def _add_human_queue_deduplication(conn: sqlite3.Connection) -> None:
    _add_column_if_missing(conn, "human_queue_items", "dedupe_key", "TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_human_queue_domain_status_type ON human_queue_items(domain, status, queue_type, id)")
    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_human_queue_pending_dedupe "
        "ON human_queue_items(domain, queue_type, dedupe_key) WHERE dedupe_key <> '' AND status = 'pending'"
    )
