from __future__ import annotations

import sqlite3
from collections import Counter, defaultdict
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.news import repository as news_repo
from ai4sec_platform.core.time import utc_now

DOMAIN = "news"


def list_news(
    conn: sqlite3.Connection,
    *,
    query: str = "",
    item_type: str = "",
    source: str = "",
    topic: str = "",
    status: str = "",
    date_from: str = "",
    date_to: str = "",
    min_score: float | None = None,
    sort: str = "score",
    page: int = 1,
    page_size: int = 30,
    operator: str = "operator",
) -> dict[str, Any]:
    clauses = ["di.domain = 'news'"]
    params: list[Any] = []
    if query:
        clauses.append("(LOWER(di.title) LIKE ? OR LOWER(di.summary) LIKE ? OR LOWER(di.source) LIKE ? OR LOWER(di.payload_json) LIKE ?)")
        value = f"%{query.lower()}%"
        params.extend([value, value, value, value])
    if item_type:
        clauses.append("di.item_type = ?")
        params.append("project" if item_type == "repo" else item_type)
    if source:
        clauses.append("di.source = ?")
        params.append(source)
    if topic:
        clauses.append("(LOWER(di.tags_json) LIKE ? OR LOWER(di.payload_json) LIKE ?)")
        value = f"%{topic.lower()}%"
        params.extend([value, value])
    if status:
        if status in {"unread", "read", "bookmarked", "later", "ignored"}:
            clauses.append("COALESCE(us.reading_state, 'unread') = ?")
            params.append(status)
        else:
            clauses.append("di.status = ?")
            params.append(status)
    if date_from:
        clauses.append("di.primary_date >= ?")
        params.append(date_from)
    if date_to:
        clauses.append("di.primary_date <= ?")
        params.append(date_to)
    if min_score is not None:
        clauses.append("COALESCE(di.score, 0) >= ?")
        params.append(min_score)
    order_by = {
        "published_at": "di.primary_date DESC, di.id DESC",
        "updated_at": "di.updated_at DESC, di.id DESC",
        "score": "COALESCE(di.score, 0) DESC, di.primary_date DESC, di.id DESC",
    }.get(sort, "COALESCE(di.score, 0) DESC, di.primary_date DESC, di.id DESC")
    where = " AND ".join(clauses)
    count_row = conn.execute(f"SELECT COUNT(*) AS count FROM domain_items di LEFT JOIN news_user_states us ON us.domain_item_id = di.id AND us.operator = ? WHERE {where}", [operator, *params]).fetchone()
    total = int(count_row["count"])
    offset = max(0, page - 1) * page_size
    rows = conn.execute(
        f"SELECT di.*, COALESCE(us.reading_state, 'unread') AS reading_state, COALESCE(us.feedback_value, '') AS feedback_value, COALESCE(us.feedback_reason, '') AS feedback_reason FROM domain_items di LEFT JOIN news_user_states us ON us.domain_item_id = di.id AND us.operator = ? WHERE {where} ORDER BY {order_by} LIMIT ? OFFSET ?",
        [operator, *params, page_size, offset],
    ).fetchall()
    return {"domain": DOMAIN, "items": [_serialize_row(row) for row in rows], "page": page, "page_size": page_size, "total": total, "filters": {"query": query, "item_type": item_type, "source": source, "topic": topic, "status": status, "date_from": date_from, "date_to": date_to, "min_score": min_score, "sort": sort}}


def today(conn: sqlite3.Connection, *, limit: int = 12, operator: str = "operator") -> dict[str, Any]:
    items = list_news(conn, page=1, page_size=limit, min_score=55, sort="score", operator=operator)["items"]
    kpis = {
        "new_count": _count(conn, "1=1"),
        "highlight_count": _count(conn, "score >= 70"),
        "paper_count": _count(conn, "item_type = 'paper'"),
        "project_count": _count(conn, "item_type = 'project'"),
        "high_value_count": _count(conn, "score >= 70"),
    }
    topics = topic_summary(conn, limit=8)
    sources = source_summary(conn)
    return {"domain": DOMAIN, "date": utc_now()[:10], "kpis": kpis, "highlights": items, "topic_summary": topics, "source_summary": sources}


def detail(conn: sqlite3.Connection, item_id: int, operator: str = "operator") -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT di.*, COALESCE(us.reading_state, 'unread') AS reading_state, COALESCE(us.feedback_value, '') AS feedback_value, COALESCE(us.feedback_reason, '') AS feedback_reason FROM domain_items di LEFT JOIN news_user_states us ON us.domain_item_id = di.id AND us.operator = ? WHERE di.domain = 'news' AND di.id = ?",
        (operator, item_id),
    ).fetchone()
    if not row:
        return None
    item = _serialize_row(row)
    item["evidence"] = repo.list_evidence(conn, DOMAIN, item_id)
    payload = item.get("payload") or {}
    related_keys = {payload.get("paper_url"), payload.get("code_url"), payload.get("repo_full_name")}
    related: list[dict[str, Any]] = []
    if any(related_keys):
        for candidate in list_news(conn, query=str(next((key for key in related_keys if key), "")), page_size=10, operator=operator)["items"]:
            if candidate["id"] != item_id:
                related.append(candidate)
    item["related_items"] = related[:10]
    return item


def reports(conn: sqlite3.Connection, *, limit: int = 30) -> dict[str, Any]:
    rows = conn.execute("SELECT * FROM news_daily_reports ORDER BY report_date DESC LIMIT ?", (limit,)).fetchall()
    return {"domain": DOMAIN, "items": [news_repo.report_to_dict(row) for row in rows]}


def report_detail(conn: sqlite3.Connection, report_date: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM news_daily_reports WHERE report_date = ?", (report_date,)).fetchone()
    if not row:
        return None
    report = news_repo.report_to_dict(row)
    report["items"] = [detail(conn, int(item_id)) for item_id in report["highlights"]]
    return report


def topic_summary(conn: sqlite3.Connection, *, limit: int = 30) -> list[dict[str, Any]]:
    counter: Counter[str] = Counter()
    latest: dict[str, str] = {}
    item_map: defaultdict[str, list[int]] = defaultdict(list)
    rows = conn.execute("SELECT id, primary_date, tags_json, payload_json FROM domain_items WHERE domain = 'news'").fetchall()
    for row in rows:
        payload = repo.loads(row["payload_json"], {})
        topics = list(dict.fromkeys([*(payload.get("topics") or []), *(repo.loads(row["tags_json"], []) or [])]))
        for topic in topics:
            if not topic or topic in {"paper", "project", "article", "tool", "report"}:
                continue
            counter[str(topic)] += 1
            item_map[str(topic)].append(int(row["id"]))
            latest[str(topic)] = max(latest.get(str(topic), ""), row["primary_date"] or "")
    return [{"topic": topic, "item_count": count, "latest_at": latest.get(topic, ""), "items": item_map[topic][:10]} for topic, count in counter.most_common(limit)]


def topic_detail(conn: sqlite3.Connection, topic: str, *, operator: str = "operator") -> dict[str, Any]:
    return {"domain": DOMAIN, "topic": topic, "items": list_news(conn, topic=topic, page_size=100, sort="published_at", operator=operator)["items"]}


def source_summary(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT source, COUNT(*) AS count FROM domain_items WHERE domain = 'news' GROUP BY source ORDER BY count DESC").fetchall()
    health = {row["name"]: row for row in conn.execute("SELECT * FROM data_sources WHERE domain = 'news' ORDER BY id DESC").fetchall()}
    return [{"id": row["source"], "name": row["source"], "count": int(row["count"]), "status": health[row["source"]]["status"] if row["source"] in health else "unknown"} for row in rows]


def apply_action(conn: sqlite3.Connection, item_id: int, action: str, *, operator: str = "operator", value: str = "", reason: str = "") -> dict[str, Any]:
    if not conn.execute("SELECT 1 FROM domain_items WHERE domain = 'news' AND id = ?", (item_id,)).fetchone():
        return {}
    states = {"read": "read", "bookmark": "bookmarked", "later": "later", "ignore": "ignored", "unignore": "unread"}
    state = states.get(action)
    if action == "feedback":
        state = None
    return news_repo.upsert_user_state(conn, item_id=item_id, operator=operator, reading_state=state, feedback_value=value if action == "feedback" else None, feedback_reason=reason if action == "feedback" else None)


def promote_to_capability(conn: sqlite3.Connection, item_id: int, *, operator: str = "operator") -> dict[str, Any]:
    item = detail(conn, item_id, operator)
    if not item:
        return {}
    rows = conn.execute("SELECT id, payload_json FROM domain_items WHERE domain = 'capabilities'").fetchall()
    for row in rows:
        payload = repo.loads(row["payload_json"], {})
        if payload.get("source_news_item_id") == item_id:
            return {"capability_id": int(row["id"]), "status": "existing"}
    payload = item.get("payload") or {}
    capability_id = repo.create_domain_item(conn, domain="capabilities", item_type="capability", title=item["title"], summary=item.get("summary", ""), score=item.get("score"), status="待能力评估", source="news", source_url=item.get("source_url", ""), primary_date=item.get("primary_date", ""), tags=["from_news", *item.get("tags", [])], metrics={"source_news_item_id": item_id}, payload={"source_news_item_id": item_id, "source_news_item": item})
    repo.create_human_queue_item(conn, domain="capabilities", item_id=capability_id, queue_type="capability_assessment", priority=3, reason="用户从资讯洞察主动转入能力评估。", payload={"source_news_item_id": item_id, "operator": operator})
    return {"capability_id": capability_id, "status": "created"}


def _count(conn: sqlite3.Connection, condition: str) -> int:
    row = conn.execute(f"SELECT COUNT(*) AS count FROM domain_items WHERE domain = 'news' AND {condition}").fetchone()
    return int(row["count"])


def _serialize_row(row: sqlite3.Row) -> dict[str, Any]:
    item = repo.row_to_dict(row)
    payload = item.get("payload") or {}
    item["item_type"] = "project" if item.get("item_type") == "repo" else item.get("item_type")
    item["highlight"] = payload.get("highlight") or item.get("summary", "")[:180]
    item["technical_points"] = payload.get("technical_points") or payload.get("topics") or []
    item["paper"] = {"arxiv_id": payload.get("external_id", ""), "authors": payload.get("authors", []), "abstract": payload.get("summary", ""), "code_url": payload.get("code_url", "")} if item["item_type"] == "paper" else None
    item["project"] = {"repo_full_name": payload.get("repo_full_name", ""), "stars": payload.get("stars", 0), "forks": payload.get("forks", 0), "language": payload.get("language", ""), "updated_at": payload.get("updated_at", ""), "linked_paper_ids": payload.get("linked_paper_ids", [])} if item["item_type"] == "project" else None
    item["user_state"] = {"reading_state": item.pop("reading_state", "unread"), "feedback_value": item.pop("feedback_value", ""), "feedback_reason": item.pop("feedback_reason", "")}
    return item
