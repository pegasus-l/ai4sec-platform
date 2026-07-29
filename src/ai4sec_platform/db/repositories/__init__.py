from __future__ import annotations

import json
import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now


def dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False)


def loads(value: str | None, fallback: Any = None) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    for key in ["tags_json", "metrics_json", "payload_json", "summary_json", "details_json", "payload_summary_json"]:
        if key in item:
            out_key = key.removesuffix("_json")
            item[out_key] = loads(item.pop(key), [] if key == "tags_json" else {})
    return item



def create_raw_artifact(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    domain: str,
    source: str,
    source_type: str = "",
    source_path: str = "",
    artifact_id: int | None = None,
    item_count: int = 0,
    payload: dict[str, Any] | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO raw_artifacts (run_id, domain, source, source_type, source_path, artifact_id, item_count, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, domain, source, source_type, source_path, artifact_id, item_count, dumps(payload or {}), utc_now()),
    )
    return int(cur.lastrowid)


def create_normalized_item(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    domain: str,
    item_key: str,
    source: str,
    source_type: str,
    title: str,
    url: str = "",
    primary_date: str = "",
    normalized: dict[str, Any] | None = None,
    raw_artifact_id: int | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO normalized_items (run_id, domain, item_key, source, source_type, title, url, primary_date, normalized_json, raw_artifact_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, domain, item_key, source, source_type, title, url, primary_date, dumps(normalized or {}), raw_artifact_id, utc_now()),
    )
    return int(cur.lastrowid)


def list_normalized_items(conn: sqlite3.Connection, *, run_id: str, domain: str = "news", limit: int = 1000) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM normalized_items WHERE run_id = ? AND domain = ? ORDER BY id LIMIT ?",
        (run_id, domain, limit),
    ).fetchall()
    return [row_to_dict(row) for row in rows]


def create_domain_item(
    conn: sqlite3.Connection,
    *,
    domain: str,
    item_type: str,
    title: str,
    summary: str = "",
    score: float | None = None,
    status: str = "active",
    source: str = "",
    source_url: str = "",
    primary_date: str = "",
    tags: list[str] | None = None,
    metrics: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
) -> int:
    now = utc_now()
    cur = conn.execute(
        """
        INSERT INTO domain_items (
            domain, item_type, title, summary, score, status, source, source_url,
            primary_date, tags_json, metrics_json, payload_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, item_type, title, summary, score, status, source, source_url, primary_date, dumps(tags or []), dumps(metrics or {}), dumps(payload or {}), now, now),
    )
    return int(cur.lastrowid)


def create_evidence(
    conn: sqlite3.Connection,
    *,
    domain: str,
    domain_item_id: int,
    evidence_type: str,
    title: str = "",
    content: str = "",
    source_url: str = "",
    confidence: float | None = None,
    payload: dict[str, Any] | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO evidence_items (
            domain, domain_item_id, evidence_type, title, content,
            source_url, confidence, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, domain_item_id, evidence_type, title, content, source_url, confidence, dumps(payload or {}), utc_now()),
    )
    return int(cur.lastrowid)


def create_pipeline_run(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    domain: str,
    pipeline_name: str,
    status: str = "success",
    started_at: str = "",
    finished_at: str = "",
    production_writes: bool = False,
    summary: dict[str, Any] | None = None,
    source_path: str = "",
) -> None:
    now = utc_now()
    existing = conn.execute("SELECT run_id, started_at, created_at FROM pipeline_runs WHERE run_id = ?", (run_id,)).fetchone()
    if existing:
        conn.execute(
            """
            UPDATE pipeline_runs
            SET domain = ?, pipeline_name = ?, status = ?, started_at = ?, finished_at = ?,
                production_writes = ?, summary_json = ?, source_path = ?
            WHERE run_id = ?
            """,
            (
                domain,
                pipeline_name,
                status,
                started_at or existing["started_at"] or now,
                finished_at,
                int(production_writes),
                dumps(summary or {}),
                source_path,
                run_id,
            ),
        )
        return
    conn.execute(
        """
        INSERT INTO pipeline_runs (
            run_id, domain, pipeline_name, status, started_at, finished_at,
            production_writes, summary_json, source_path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, domain, pipeline_name, status, started_at or now, finished_at, int(production_writes), dumps(summary or {}), source_path, now),
    )


def create_task_run(conn: sqlite3.Connection, *, run_id: str, step_name: str, status: str = "success", metrics: dict[str, Any] | None = None, error_message: str = "") -> None:
    now = utc_now()
    conn.execute(
        """
        INSERT INTO task_runs (run_id, step_name, status, started_at, finished_at, metrics_json, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, step_name, status, now, now, dumps(metrics or {}), error_message),
    )


def create_artifact(conn: sqlite3.Connection, *, run_id: str, artifact_type: str, path: str, sha256: str = "", bytes_size: int = 0, payload_summary: dict[str, Any] | None = None) -> None:
    conn.execute(
        """
        INSERT INTO artifacts (run_id, artifact_type, path, sha256, bytes, payload_summary_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, artifact_type, path, sha256, bytes_size, dumps(payload_summary or {}), utc_now()),
    )


def create_data_source(conn: sqlite3.Connection, *, domain: str, name: str, source_type: str, status: str = "ok", latest_at: str = "", health: str = "ok", summary: dict[str, Any] | None = None) -> None:
    conn.execute(
        """
        INSERT INTO data_sources (domain, name, source_type, status, latest_at, health, summary_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, name, source_type, status, latest_at, health, dumps(summary or {}), utc_now()),
    )


def create_quality_audit(conn: sqlite3.Connection, *, domain: str, audit_type: str, status: str, score: float | None = None, summary: str = "", details: dict[str, Any] | None = None) -> None:
    conn.execute(
        """
        INSERT INTO quality_audits (domain, audit_type, status, score, summary, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, audit_type, status, score, summary, dumps(details or {}), utc_now()),
    )


def create_human_queue_item(conn: sqlite3.Connection, *, domain: str, item_id: int | None, queue_type: str, status: str = "pending", priority: int = 3, reason: str = "", assignee: str = "", payload: dict[str, Any] | None = None) -> None:
    now = utc_now()
    conn.execute(
        """
        INSERT INTO human_queue_items (domain, item_id, queue_type, status, priority, reason, assignee, payload_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, item_id, queue_type, status, priority, reason, assignee, dumps(payload or {}), now, now),
    )



def create_model_call(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    agent_name: str,
    model_profile: str,
    provider: str = "local_rules",
    status: str = "success",
    input_payload: dict[str, Any] | None = None,
    output_payload: dict[str, Any] | None = None,
    latency_ms: int = 0,
    error_message: str = "",
    task_run_id: str = "",
) -> int:
    cur = conn.execute(
        """
        INSERT INTO model_calls (run_id, task_run_id, agent_name, model_profile, provider, status, input_json, output_json, latency_ms, error_message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, task_run_id, agent_name, model_profile, provider, status, dumps(input_payload or {}), dumps(output_payload or {}), latency_ms, error_message, utc_now()),
    )
    return int(cur.lastrowid)


def update_domain_item(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    status: str | None = None,
    score: float | None = None,
    metrics: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    title: str | None = None,
    summary: str | None = None,
    source: str | None = None,
    source_url: str | None = None,
    primary_date: str | None = None,
    tags: list[str] | None = None,
) -> None:
    existing = conn.execute("SELECT metrics_json, payload_json FROM domain_items WHERE id = ?", (item_id,)).fetchone()
    if not existing:
        return
    current_metrics = loads(existing["metrics_json"], {})
    current_payload = loads(existing["payload_json"], {})
    if metrics:
        current_metrics.update(metrics)
    if payload:
        current_payload.update(payload)
    fields = ["metrics_json = ?", "payload_json = ?", "updated_at = ?"]
    params: list[Any] = [dumps(current_metrics), dumps(current_payload), utc_now()]
    if status is not None:
        fields.append("status = ?")
        params.append(status)
    if score is not None:
        fields.append("score = ?")
        params.append(score)
    if title is not None:
        fields.append("title = ?")
        params.append(title)
    if summary is not None:
        fields.append("summary = ?")
        params.append(summary)
    if source is not None:
        fields.append("source = ?")
        params.append(source)
    if source_url is not None:
        fields.append("source_url = ?")
        params.append(source_url)
    if primary_date is not None:
        fields.append("primary_date = ?")
        params.append(primary_date)
    if tags is not None:
        fields.append("tags_json = ?")
        params.append(dumps(tags))
    params.append(item_id)
    conn.execute(f"UPDATE domain_items SET {', '.join(fields)} WHERE id = ?", params)


def list_domain_items(conn: sqlite3.Connection, domain: str, *, item_type: str | None = None, limit: int = 50, status: str | None = None) -> list[dict[str, Any]]:
    sql = "SELECT * FROM domain_items WHERE domain = ?"
    params: list[Any] = [domain]
    if item_type:
        sql += " AND item_type = ?"
        params.append(item_type)
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY COALESCE(score, 0) DESC, primary_date DESC, id DESC LIMIT ?"
    params.append(limit)
    return [row_to_dict(row) for row in conn.execute(sql, params).fetchall()]


def get_domain_item(conn: sqlite3.Connection, domain: str, item_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM domain_items WHERE domain = ? AND id = ?", (domain, item_id)).fetchone()
    if not row:
        return None
    item = row_to_dict(row)
    item["evidence"] = list_evidence(conn, domain, item_id)
    return item


def list_evidence(conn: sqlite3.Connection, domain: str, item_id: int) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM evidence_items WHERE domain = ? AND domain_item_id = ? ORDER BY id", (domain, item_id)).fetchall()
    return [row_to_dict(row) for row in rows]


def list_table(conn: sqlite3.Connection, table: str, *, domain: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    allowed = {"pipeline_runs", "task_runs", "artifacts", "data_sources", "quality_audits", "human_queue_items", "raw_artifacts", "normalized_items", "model_calls", "capability_repro_tasks"}
    if table not in allowed:
        raise ValueError(f"Unsupported table: {table}")
    if domain and table in {"pipeline_runs", "data_sources", "quality_audits", "human_queue_items"}:
        rows = conn.execute(f"SELECT * FROM {table} WHERE domain = ? ORDER BY id DESC LIMIT ?", (domain, limit)).fetchall()
    else:
        rows = conn.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [row_to_dict(row) for row in rows]


def count_by_domain(conn: sqlite3.Connection, domain: str) -> int:
    row = conn.execute("SELECT COUNT(*) AS count FROM domain_items WHERE domain = ?", (domain,)).fetchone()
    return int(row["count"])


# ============================================================================
# capability_repro_tasks - 复现任务 CRUD（迁移自旧 v1 db.py）
# ============================================================================

_REPRO_UPDATABLE_FIELDS = {
    "status",
    "container_name",
    "workspace_path",
    "log",
    "result",
    "finished_at",
    "cleaned_at",
    "trigger",
    "report_json",
    "web_port",
    "web_url",
    "started_at",
    "updated_at",
    "worker_id",
    "heartbeat_at",
    "cancel_requested",
    "cleanup_requested",
}


def create_repro_task(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    repo_url: str,
    trigger: str = "manual",
) -> int:
    """创建复现任务，返回 task_id"""
    cur = conn.execute(
        "INSERT INTO capability_repro_tasks (item_id, repo_url, status, created_at, updated_at, trigger) "
        "VALUES (?, ?, 'queued', ?, ?, ?)",
        (item_id, repo_url, utc_now(), utc_now(), trigger),
    )
    return int(cur.lastrowid)


def get_repro_task(conn: sqlite3.Connection, task_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
    if not row:
        return None
    item = dict(row)
    # report_json → report（保持 _json 后缀的字段也保留，方便 row_to_dict 调用方）
    return item


def list_repro_tasks(
    conn: sqlite3.Connection,
    *,
    item_id: int | None = None,
    limit: int = 200,
    include_cleaned: bool = False,
) -> list[dict[str, Any]]:
    """列出复现任务，可按 item_id 过滤；默认排除 cleaned"""
    if item_id is not None:
        sql = "SELECT * FROM capability_repro_tasks WHERE item_id = ?"
        params: list[Any] = [item_id]
        if not include_cleaned:
            sql += " AND status != 'cleaned'"
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
    else:
        sql = "SELECT * FROM capability_repro_tasks"
        params = []
        if not include_cleaned:
            sql += " WHERE status != 'cleaned'"
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def update_repro_task(conn: sqlite3.Connection, *, task_id: int, **fields: Any) -> None:
    """更新复现任务字段，只允许白名单内字段"""
    sets, vals = [], []
    fields.setdefault("updated_at", utc_now())
    for k, v in fields.items():
        if k in _REPRO_UPDATABLE_FIELDS:
            sets.append(f"{k} = ?")
            vals.append(v)
    if not sets:
        return
    vals.append(task_id)
    conn.execute(f"UPDATE capability_repro_tasks SET {', '.join(sets)} WHERE id = ?", vals)


def append_repro_log(conn: sqlite3.Connection, *, task_id: int, line: str) -> None:
    """追加日志行到 task 的 log 字段（累积）"""
    conn.execute(
        "UPDATE capability_repro_tasks SET log = log || ? WHERE id = ?",
        (line + "\n", task_id),
    )


def get_succeeded_repro_item_ids(conn: sqlite3.Connection) -> set[int]:
    """已成功复现的 item_id 集合（含 status=success 或 partial）"""
    rows = conn.execute(
        "SELECT DISTINCT item_id FROM capability_repro_tasks WHERE status IN ('success', 'partial')"
    ).fetchall()
    return {row["item_id"] for row in rows}


def get_active_repro_item_ids(conn: sqlite3.Connection) -> set[int]:
    """正在复现中的 item_id 集合"""
    rows = conn.execute(
        "SELECT DISTINCT item_id FROM capability_repro_tasks WHERE status IN ('queued', 'running')"
    ).fetchall()
    return {row["item_id"] for row in rows}
