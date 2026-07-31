from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo


def get_item_id_by_key(conn: sqlite3.Connection, canonical_key: str) -> int | None:
    row = conn.execute("SELECT domain_item_id FROM news_item_index WHERE canonical_key = ?", (canonical_key,)).fetchone()
    return int(row["domain_item_id"]) if row else None


def bind_item_key(conn: sqlite3.Connection, canonical_key: str, item_id: int) -> None:
    now = utc_now()
    conn.execute(
        """
        INSERT INTO news_item_index (canonical_key, domain_item_id, first_seen_at, last_seen_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(canonical_key) DO UPDATE SET
            domain_item_id = excluded.domain_item_id,
            last_seen_at = excluded.last_seen_at
        """,
        (canonical_key, item_id, now, now),
    )


def update_news_item(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    item_type: str,
    title: str,
    summary: str,
    score: float,
    status: str,
    source: str,
    source_url: str,
    primary_date: str,
    tags: list[str],
    metrics: dict[str, Any],
    payload: dict[str, Any],
) -> None:
    conn.execute(
        """
        UPDATE domain_items
        SET item_type = ?, title = ?, summary = ?, score = ?, status = ?, source = ?,
            source_url = ?, primary_date = ?, tags_json = ?, metrics_json = ?,
            payload_json = ?, updated_at = ?
        WHERE id = ? AND domain = 'news'
        """,
        (
            item_type,
            title,
            summary,
            score,
            status,
            source,
            source_url,
            primary_date,
            repo.dumps(tags),
            repo.dumps(metrics),
            repo.dumps(payload),
            utc_now(),
            item_id,
        ),
    )


def get_user_state(conn: sqlite3.Connection, item_id: int, operator: str = "operator") -> dict[str, Any]:
    row = conn.execute(
        "SELECT * FROM news_user_states WHERE domain_item_id = ? AND operator = ?",
        (item_id, operator),
    ).fetchone()
    return dict(row) if row else {"domain_item_id": item_id, "operator": operator, "reading_state": "unread", "feedback_value": "", "feedback_reason": ""}


def upsert_user_state(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    operator: str,
    reading_state: str | None = None,
    feedback_value: str | None = None,
    feedback_reason: str | None = None,
) -> dict[str, Any]:
    current = get_user_state(conn, item_id, operator)
    now = utc_now()
    conn.execute(
        """
        INSERT INTO news_user_states (
            domain_item_id, operator, reading_state, feedback_value, feedback_reason, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(domain_item_id, operator) DO UPDATE SET
            reading_state = excluded.reading_state,
            feedback_value = excluded.feedback_value,
            feedback_reason = excluded.feedback_reason,
            updated_at = excluded.updated_at
        """,
        (
            item_id,
            operator,
            reading_state or current["reading_state"],
            current["feedback_value"] if feedback_value is None else feedback_value,
            current["feedback_reason"] if feedback_reason is None else feedback_reason,
            current.get("created_at") or now,
            now,
        ),
    )
    return get_user_state(conn, item_id, operator)


def upsert_daily_report(
    conn: sqlite3.Connection,
    *,
    report_date: str,
    title: str,
    summary: str,
    highlights: list[int],
    topic_sections: list[dict[str, Any]],
    metrics: dict[str, Any],
    run_id: str,
) -> None:
    now = utc_now()
    conn.execute(
        """
        INSERT INTO news_daily_reports (
            report_date, title, summary, highlights_json, topic_sections_json,
            metrics_json, status, run_id, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'shadow', ?, ?, ?)
        ON CONFLICT(report_date) DO UPDATE SET
            title = excluded.title,
            summary = excluded.summary,
            highlights_json = excluded.highlights_json,
            topic_sections_json = excluded.topic_sections_json,
            metrics_json = excluded.metrics_json,
            run_id = excluded.run_id,
            updated_at = excluded.updated_at
        """,
        (report_date, title, summary, repo.dumps(highlights), repo.dumps(topic_sections), repo.dumps(metrics), run_id, now, now),
    )


def get_daily_report_item_ids(conn: sqlite3.Connection, report_date: str) -> list[int]:
    row = conn.execute(
        "SELECT highlights_json, topic_sections_json, metrics_json FROM news_daily_reports WHERE report_date = ?",
        (report_date,),
    ).fetchone()
    if not row:
        return []
    metrics = repo.loads(row["metrics_json"], {})
    item_ids = [int(value) for value in metrics.get("item_ids") or [] if str(value).isdigit()] if isinstance(metrics, dict) else []
    item_ids.extend(int(value) for value in repo.loads(row["highlights_json"], []) if str(value).isdigit())
    for section in repo.loads(row["topic_sections_json"], []):
        if not isinstance(section, dict):
            continue
        item_ids.extend(int(value) for value in section.get("item_ids") or [] if str(value).isdigit())
    return list(dict.fromkeys(item_ids))


def report_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["highlights"] = repo.loads(item.pop("highlights_json"), [])
    item["topic_sections"] = repo.loads(item.pop("topic_sections_json"), [])
    item["metrics"] = repo.loads(item.pop("metrics_json"), {})
    return item
