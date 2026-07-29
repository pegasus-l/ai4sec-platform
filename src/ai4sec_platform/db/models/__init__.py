from __future__ import annotations

import sqlite3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS domain_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    item_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    score REAL,
    status TEXT NOT NULL DEFAULT 'active',
    source TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    primary_date TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    metrics_json TEXT NOT NULL DEFAULT '{}',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domain_items_domain ON domain_items(domain);
CREATE INDEX IF NOT EXISTS idx_domain_items_type ON domain_items(domain, item_type);
CREATE INDEX IF NOT EXISTS idx_domain_items_score ON domain_items(domain, score DESC);


CREATE TABLE IF NOT EXISTS raw_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT '',
    source_path TEXT NOT NULL DEFAULT '',
    artifact_id INTEGER,
    item_count INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_run ON raw_artifacts(run_id);
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_domain_source ON raw_artifacts(domain, source);

CREATE TABLE IF NOT EXISTS normalized_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    item_key TEXT NOT NULL,
    source TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    primary_date TEXT NOT NULL DEFAULT '',
    normalized_json TEXT NOT NULL DEFAULT '{}',
    raw_artifact_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY(raw_artifact_id) REFERENCES raw_artifacts(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_normalized_run ON normalized_items(run_id);
CREATE INDEX IF NOT EXISTS idx_normalized_domain ON normalized_items(domain);
CREATE INDEX IF NOT EXISTS idx_normalized_key ON normalized_items(domain, item_key);

CREATE TABLE IF NOT EXISTS evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    domain_item_id INTEGER NOT NULL,
    evidence_type TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    confidence REAL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(domain_item_id) REFERENCES domain_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_evidence_item ON evidence_items(domain_item_id);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    pipeline_name TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    production_writes INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT NOT NULL DEFAULT '{}',
    source_path TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_domain ON pipeline_runs(domain);

CREATE TABLE IF NOT EXISTS task_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    metrics_json TEXT NOT NULL DEFAULT '{}',
    error_message TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_task_runs_run_id ON task_runs(run_id);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    bytes INTEGER NOT NULL DEFAULT 0,
    payload_summary_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_artifacts_run_id ON artifacts(run_id);


CREATE TABLE IF NOT EXISTS model_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    task_run_id TEXT NOT NULL DEFAULT '',
    agent_name TEXT NOT NULL,
    model_profile TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    input_json TEXT NOT NULL DEFAULT '{}',
    output_json TEXT NOT NULL DEFAULT '{}',
    latency_ms INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_model_calls_run ON model_calls(run_id);
CREATE INDEX IF NOT EXISTS idx_model_calls_agent ON model_calls(agent_name);

CREATE TABLE IF NOT EXISTS data_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    latest_at TEXT NOT NULL DEFAULT '',
    health TEXT NOT NULL DEFAULT 'unknown',
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_data_sources_domain ON data_sources(domain);

CREATE TABLE IF NOT EXISTS quality_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    audit_type TEXT NOT NULL,
    status TEXT NOT NULL,
    score REAL,
    summary TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quality_audits_domain ON quality_audits(domain);

CREATE TABLE IF NOT EXISTS human_queue_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    item_id INTEGER,
    queue_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 3,
    reason TEXT NOT NULL DEFAULT '',
    assignee TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_human_queue_domain ON human_queue_items(domain);

CREATE TABLE IF NOT EXISTS news_item_index (
    canonical_key TEXT PRIMARY KEY,
    domain_item_id INTEGER NOT NULL UNIQUE,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    FOREIGN KEY(domain_item_id) REFERENCES domain_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_news_item_index_item ON news_item_index(domain_item_id);

CREATE TABLE IF NOT EXISTS news_user_states (
    domain_item_id INTEGER NOT NULL,
    operator TEXT NOT NULL DEFAULT 'operator',
    reading_state TEXT NOT NULL DEFAULT 'unread',
    feedback_value TEXT NOT NULL DEFAULT '',
    feedback_reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(domain_item_id, operator),
    FOREIGN KEY(domain_item_id) REFERENCES domain_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_news_user_states_operator ON news_user_states(operator, reading_state);

CREATE TABLE IF NOT EXISTS news_daily_reports (
    report_date TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    highlights_json TEXT NOT NULL DEFAULT '[]',
    topic_sections_json TEXT NOT NULL DEFAULT '[]',
    metrics_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'shadow',
    run_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capability_repro_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    repo_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    container_name TEXT NOT NULL DEFAULT '',
    workspace_path TEXT NOT NULL DEFAULT '',
    log TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    cleaned_at TEXT NOT NULL DEFAULT '',
    trigger TEXT NOT NULL DEFAULT 'manual',
    report_json TEXT NOT NULL DEFAULT '{}',
    web_port INTEGER,
    web_url TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (item_id) REFERENCES domain_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cap_repro_item ON capability_repro_tasks(item_id);
CREATE INDEX IF NOT EXISTS idx_cap_repro_status ON capability_repro_tasks(status);
CREATE INDEX IF NOT EXISTS idx_cap_repro_created ON capability_repro_tasks(created_at DESC);
"""


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    # Migrations
    try: conn.execute("ALTER TABLE domain_items ADD COLUMN last_synced_at TEXT")
    except Exception: pass
    try: conn.execute("ALTER TABLE human_queue_items ADD COLUMN queue_source TEXT DEFAULT 'pipeline'")
    except Exception: pass
    conn.commit()


SUPPORTED_DOMAINS = frozenset({"news", "capabilities", "threats", "vulnerabilities"})


def reset_domain(conn: sqlite3.Connection, domain: str) -> None:
    if domain not in SUPPORTED_DOMAINS:
        raise ValueError(f"Unsupported domain reset: {domain}")
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM pipeline_runs WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM human_queue_items WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM quality_audits WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM data_sources WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM evidence_items WHERE domain = ?", (domain,))
        conn.execute("DELETE FROM domain_items WHERE domain = ?", (domain,))
        if domain == "news":
            conn.execute("DELETE FROM news_daily_reports")
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def reset_db(conn: sqlite3.Connection) -> None:
    tables = [
        "news_daily_reports",
        "news_user_states",
        "news_item_index",
        "capability_repro_tasks",
        "human_queue_items",
        "quality_audits",
        "normalized_items",
        "raw_artifacts",
        "data_sources",
        "model_calls",
        "artifacts",
        "task_runs",
        "pipeline_runs",
        "evidence_items",
        "domain_items",
    ]
    for table in tables:
        conn.execute(f"DROP TABLE IF EXISTS {table}")
    conn.commit()
    init_db(conn)
