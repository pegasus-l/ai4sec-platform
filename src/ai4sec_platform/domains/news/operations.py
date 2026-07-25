from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo

NEWS_SOURCES = ("arxiv", "github", "rss", "asis", "awesome", "x")


def overview(conn: sqlite3.Connection) -> dict[str, Any]:
    counts = {row["item_type"]: int(row["count"]) for row in conn.execute("SELECT item_type, COUNT(*) AS count FROM domain_items WHERE domain = 'news' GROUP BY item_type")}
    latest_run = conn.execute("SELECT * FROM pipeline_runs WHERE domain = 'news' ORDER BY id DESC LIMIT 1").fetchone()
    report = conn.execute("SELECT report_date, title, metrics_json FROM news_daily_reports ORDER BY report_date DESC LIMIT 1").fetchone()
    model = _model_metrics(conn, latest_run["run_id"] if latest_run else "")
    tasks = _run_tasks(conn, latest_run["run_id"] if latest_run else "")
    sources = source_status(conn)
    return {
        "items": {"total": sum(counts.values()), "papers": counts.get("paper", 0), "projects": counts.get("project", 0)},
        "latest_run": _run_payload(conn, latest_run) if latest_run else None,
        "latest_report": {"report_date": report["report_date"], "title": report["title"], "metrics": repo.loads(report["metrics_json"], {})} if report else None,
        "sources": sources,
        "models": model,
        "processing": _processing_summary(tasks, sources),
    }


def list_runs(conn: sqlite3.Connection, limit: int = 30) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM pipeline_runs WHERE domain = 'news' ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [_run_payload(conn, row) for row in rows]


def run_detail(conn: sqlite3.Connection, run_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM pipeline_runs WHERE domain = 'news' AND run_id = ?", (run_id,)).fetchone()
    if not row:
        return None
    result = _run_payload(conn, row)
    result["tasks"] = [{**repo.row_to_dict(task), "metrics": repo.loads(task["metrics_json"], {})} for task in conn.execute("SELECT * FROM task_runs WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
    result["artifacts"] = [{**repo.row_to_dict(artifact), "payload_summary": repo.loads(artifact["payload_summary_json"], {})} for artifact in conn.execute("SELECT * FROM artifacts WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]
    result["models"] = _model_metrics(conn, run_id)
    return result


def source_status(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    item_counts = {row["source"]: int(row["count"]) for row in conn.execute("SELECT source, COUNT(*) AS count FROM domain_items WHERE domain = 'news' GROUP BY source")}
    rows = conn.execute("SELECT * FROM data_sources WHERE domain = 'news' ORDER BY id DESC").fetchall()
    latest = {}
    for row in rows:
        latest.setdefault(str(row["name"]).lower(), row)
    result = []
    for source in NEWS_SOURCES:
        row = latest.get(source)
        summary = repo.loads(row["summary_json"], {}) if row else {}
        errors = [str(error) for error in summary.get("errors", []) if error]
        result.append({
            "id": source,
            "name": source,
            "status": row["status"] if row else "unknown",
            "health": row["health"] if row else "unknown",
            "latest_at": (row["latest_at"] or row["created_at"]) if row else "",
            "item_count": item_counts.get(source, 0),
            "collected_count": int(summary.get("items") or 0),
            "error_count": len(errors),
            "errors": errors,
            "summary": summary,
        })
    return result


def quality(conn: sqlite3.Connection) -> dict[str, Any]:
    latest = conn.execute("SELECT run_id FROM pipeline_runs WHERE domain = 'news' ORDER BY id DESC LIMIT 1").fetchone()
    run_id = latest["run_id"] if latest else ""
    tasks = _run_tasks(conn, run_id)
    audits = [{**repo.row_to_dict(row), "details": repo.loads(row["details_json"], {})} for row in conn.execute("SELECT * FROM quality_audits WHERE domain = 'news' ORDER BY id DESC LIMIT 20").fetchall()]
    sources = source_status(conn)
    return {"run_id": run_id, "tasks": tasks, "models": _model_metrics(conn, run_id), "audits": audits, "processing": _processing_summary(tasks, sources)}


def _run_tasks(conn: sqlite3.Connection, run_id: str) -> list[dict[str, Any]]:
    if not run_id:
        return []
    return [{"id": row["id"], "step_name": row["step_name"], "status": row["status"], "metrics": repo.loads(row["metrics_json"], {}), "error_message": row["error_message"]} for row in conn.execute("SELECT * FROM task_runs WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()]


def _processing_summary(tasks: list[dict[str, Any]], sources: list[dict[str, Any]]) -> dict[str, Any]:
    by_name = {task["step_name"]: task.get("metrics") or {} for task in tasks}
    collect = by_name.get("collect_news_sources", {})
    normalize = by_name.get("normalize_news_items", {})
    dedupe = by_name.get("deduplicate_news_candidates", {})
    gate = by_name.get("gate_news_candidates_with_tech_map", {})
    enrich = by_name.get("enrich_news_candidates_with_model", {})
    build = by_name.get("build_news_items", {})
    source_failures = sum(int(source.get("error_count") or 0) for source in sources)
    task_failures = sum(1 for task in tasks if task.get("status") == "failed")
    model_failures = int(gate.get("failed") or 0) + int(enrich.get("failed") or 0)
    return {
        "collected": int(collect.get("items") or sum(int(source.get("collected_count") or 0) for source in sources)),
        "normalized": int(normalize.get("normalized_items") or 0),
        "deduped": int(dedupe.get("deduped_items") or 0),
        "gate_passed": int(gate.get("passed") or 0) + int(gate.get("needs_review") or 0),
        "reviewed": int(enrich.get("selected") or 0) + int(enrich.get("watch") or 0),
        "published": int(build.get("items") or build.get("created") or 0),
        "failures": {"source": source_failures, "task": task_failures, "model": model_failures, "total": source_failures + task_failures + model_failures},
    }


def _run_payload(conn: sqlite3.Connection, row: sqlite3.Row) -> dict[str, Any]:
    data = repo.row_to_dict(row)
    data["summary"] = repo.loads(row["summary_json"], {})
    task_counts = conn.execute("SELECT status, COUNT(*) AS count FROM task_runs WHERE run_id = ? GROUP BY status", (row["run_id"],)).fetchall()
    data["task_counts"] = {item["status"]: int(item["count"]) for item in task_counts}
    return data


def _model_metrics(conn: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    if not run_id:
        return {"total": 0, "success": 0, "failed": 0, "retryable_failure": 0, "cache_hits": 0, "avg_latency_ms": 0, "agents": []}
    rows = conn.execute("SELECT agent_name, provider, model_profile, status, COUNT(*) AS count, AVG(latency_ms) AS avg_latency FROM model_calls WHERE run_id = ? GROUP BY agent_name, provider, model_profile, status", (run_id,)).fetchall()
    agents: dict[tuple[str, str, str], dict[str, Any]] = {}
    totals = {"total": 0, "success": 0, "failed": 0, "retryable_failure": 0}
    latency_sum = 0.0
    for row in rows:
        count = int(row["count"])
        key = (row["agent_name"], row["provider"], row["model_profile"])
        agent = agents.setdefault(key, {"agent_name": key[0], "provider": key[1], "model_profile": key[2], "total": 0, "success": 0, "failed": 0, "retryable_failure": 0, "avg_latency_ms": 0})
        agent["total"] += count
        agent[row["status"]] = agent.get(row["status"], 0) + count
        agent["avg_latency_ms"] = round(float(row["avg_latency"] or 0))
        totals["total"] += count
        totals[row["status"]] = totals.get(row["status"], 0) + count
        latency_sum += float(row["avg_latency"] or 0) * count
    task_rows = conn.execute("SELECT metrics_json FROM task_runs WHERE run_id = ? AND step_name IN ('gate_news_candidates_with_tech_map', 'enrich_news_candidates_with_model')", (run_id,)).fetchall()
    cache_hits = sum(int(repo.loads(row["metrics_json"], {}).get("cache_hits") or 0) for row in task_rows)
    return {**totals, "cache_hits": cache_hits, "avg_latency_ms": round(latency_sum / totals["total"]) if totals["total"] else 0, "agents": list(agents.values())}
