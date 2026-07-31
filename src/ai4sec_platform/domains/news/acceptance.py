from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo


DAILY_PIPELINE = "news.daily_pipeline"
LOCAL_MODEL_PROVIDERS = {"", "unknown", "local_rules", "rule_based", "offline"}


def build_news_daily_acceptance(
    conn: sqlite3.Connection,
    *,
    required_sources: list[str],
    disabled_sources: list[str] | None = None,
    run_ids: list[str] | None = None,
    required_cycles: int = 3,
    current_model: dict[str, Any] | None = None,
) -> dict[str, Any]:
    requested_run_ids = list(dict.fromkeys(run_ids or []))
    selected_runs = _select_runs(conn, run_ids=run_ids, limit=max(required_cycles * 3, len(run_ids or [])))
    selected_run_ids = {str(run["run_id"]) for run in selected_runs}
    missing_run_ids = [run_id for run_id in requested_run_ids if run_id not in selected_run_ids]
    cycles = [_build_cycle(conn, run, required_sources) for run in selected_runs]
    qualified_runs = [cycle for cycle in cycles if cycle["qualified"]]
    qualified_dates = sorted({cycle["report_date"] for cycle in qualified_runs if cycle["report_date"]})
    health = _latest_health(conn, [*required_sources, *(disabled_sources or [])])
    unhealthy_sources = [source for source in required_sources if health.get(source, {}).get("status") != "healthy"]
    current_model = current_model or {"provider": "unknown", "configured": False, "model": ""}
    model_ready = bool(current_model.get("configured")) and str(current_model.get("provider") or "") not in LOCAL_MODEL_PROVIDERS
    if len(qualified_dates) >= required_cycles and not missing_run_ids:
        status = "pass"
    elif missing_run_ids or (cycles and any(not cycle["qualified"] for cycle in cycles)):
        status = "fail"
    else:
        status = "in_progress"
    return {
        "status": status,
        "pipeline_name": DAILY_PIPELINE,
        "required_cycles": required_cycles,
        "selected_cycles": len(cycles),
        "requested_run_ids": requested_run_ids,
        "missing_run_ids": missing_run_ids,
        "qualified_runs": len(qualified_runs),
        "qualified_cycles": len(qualified_dates),
        "qualified_dates": qualified_dates,
        "required_sources": required_sources,
        "disabled_sources": disabled_sources or [],
        "ready_to_start_cycle": not unhealthy_sources and model_ready,
        "unhealthy_sources": unhealthy_sources,
        "model_ready": model_ready,
        "current_model": current_model,
        "source_health": health,
        "cycles": cycles,
        "remaining_cycles": max(0, required_cycles - len(qualified_dates)),
    }


def render_news_daily_acceptance_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 资讯洞察连续日更验收报告",
        "",
        f"- 验收状态：`{report['status']}`",
        f"- 合格周期：`{report['qualified_cycles']}/{report['required_cycles']}`",
        f"- 合格业务日期：{', '.join(report['qualified_dates']) or '暂无'}",
        f"- 当前可启动真实周期：`{str(report['ready_to_start_cycle']).lower()}`",
        f"- 当前异常启用源：{', '.join(report['unhealthy_sources']) or '无'}",
        f"- 当前模型：`{report['current_model'].get('provider')}/{report['current_model'].get('model')}`，可用：`{str(report['model_ready']).lower()}`",
        f"- 未找到的指定 Run：{', '.join(report['missing_run_ids']) or '无'}",
        "",
        "| 日期 | Run | 状态 | 采集 | 去重率 | 入选率 | Schema 通过率 | 模型 Provider | 合格 |",
        "|---|---|---|---:|---:|---:|---:|---|---|",
    ]
    for cycle in report["cycles"]:
        lines.append(
            "| {date} | `{run_id}` | {status} | {collected} | {duplicate_rate} | {selection_rate} | {schema_rate} | {providers} | {qualified} |".format(
                date=cycle["report_date"] or "-",
                run_id=cycle["run_id"],
                status=cycle["run_status"],
                collected=cycle["metrics"]["collected_items"],
                duplicate_rate=_percent(cycle["metrics"]["duplicate_rate"]),
                selection_rate=_percent(cycle["metrics"]["selection_rate"]),
                schema_rate=_percent(cycle["metrics"]["schema_pass_rate"]),
                providers=", ".join(cycle["model_providers"]) or "-",
                qualified="是" if cycle["qualified"] else "否",
            )
        )
    lines.extend(["", "## 周期明细", ""])
    for cycle in report["cycles"]:
        lines.extend([
            f"### {cycle['report_date'] or '未知日期'} · `{cycle['run_id']}`",
            "",
            f"- 不合格原因：{'; '.join(cycle['failure_reasons']) or '无'}",
            "- 来源采集量：" + ", ".join(f"{name}={details['items']}" for name, details in cycle["sources"].items()),
            f"- 来源错误：{', '.join(name for name, details in cycle['sources'].items() if details['errors']) or '无'}",
            f"- 模型调用：成功 {cycle['model_calls']['success']}，Schema 异常 {cycle['model_calls']['schema_invalid']}，最终失败 {cycle['model_calls']['failed']}，重试中失败 {cycle['model_calls']['retryable_failure']}",
            f"- 人工队列：pending={cycle['human_queue']['pending']}，resolved={cycle['human_queue']['resolved']}，rejected={cycle['human_queue']['rejected']}",
            "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def _select_runs(conn: sqlite3.Connection, *, run_ids: list[str] | None, limit: int) -> list[sqlite3.Row]:
    if run_ids:
        rows = []
        for run_id in dict.fromkeys(run_ids):
            row = conn.execute(
                "SELECT * FROM pipeline_runs WHERE run_id = ? AND pipeline_name = ?",
                (run_id, DAILY_PIPELINE),
            ).fetchone()
            if row:
                rows.append(row)
        return rows
    return conn.execute(
        "SELECT * FROM pipeline_runs WHERE pipeline_name = ? ORDER BY id DESC LIMIT ?",
        (DAILY_PIPELINE, limit),
    ).fetchall()[::-1]


def _build_cycle(conn: sqlite3.Connection, run: sqlite3.Row, required_sources: list[str]) -> dict[str, Any]:
    run_id = str(run["run_id"])
    summary = repo.loads(run["summary_json"], {})
    tasks = {
        row["step_name"]: {"status": row["status"], "metrics": repo.loads(row["metrics_json"], {})}
        for row in conn.execute("SELECT step_name, status, metrics_json FROM task_runs WHERE run_id = ?", (run_id,)).fetchall()
    }
    sources = _source_results(conn, run_id, required_sources)
    report_date = str((summary.get("params") or {}).get("date") or "")
    report_task = tasks.get("build_news_daily_report") or {}
    if not report_date and report_task.get("status") in {"success", "restored"}:
        report_row = conn.execute("SELECT report_date FROM news_daily_reports WHERE run_id = ?", (run_id,)).fetchone()
        report_date = str(report_row["report_date"]) if report_row else ""
    gate = (tasks.get("gate_news_candidates_with_tech_map") or {}).get("metrics") or {}
    review = (tasks.get("enrich_news_candidates_with_model") or {}).get("metrics") or {}
    dedupe = (tasks.get("deduplicate_news_candidates") or {}).get("metrics") or {}
    built = (tasks.get("build_news_items") or {}).get("metrics") or {}
    model_calls = _model_call_metrics(conn, run_id)
    human_queue = _human_queue_metrics(conn, run_id)
    schema_total = int(gate.get("candidates") or 0) + int(review.get("candidates") or 0)
    schema_invalid = int(gate.get("schema_invalid") or 0) + int(review.get("schema_invalid") or 0)
    dedupe_input = int(dedupe.get("input_items") or 0)
    deduped_items = int(dedupe.get("deduped_items") or 0)
    selected_items = int(built.get("items") or 0)
    model_providers = sorted(model_calls["providers"])
    failure_reasons = []
    if run["status"] != "success":
        failure_reasons.append(f"run_status={run['status']}")
    missing_sources = [source for source in required_sources if not sources[source]["present"]]
    failed_sources = [source for source in required_sources if sources[source]["errors"]]
    if missing_sources:
        failure_reasons.append(f"missing_sources={','.join(missing_sources)}")
    if failed_sources:
        failure_reasons.append(f"failed_sources={','.join(failed_sources)}")
    if report_task.get("status") not in {"success", "restored"} or not report_date:
        failure_reasons.append("daily_report_missing")
    if schema_total <= 0:
        failure_reasons.append("schema_not_exercised")
    if schema_invalid or int(gate.get("failed") or 0) or int(review.get("failed") or 0):
        failure_reasons.append("model_schema_or_call_failure")
    if not model_providers or any(provider in LOCAL_MODEL_PROVIDERS for provider in model_providers):
        failure_reasons.append("real_model_not_used")
    return {
        "run_id": run_id,
        "run_status": str(run["status"]),
        "started_at": str(run["started_at"]),
        "finished_at": str(run["finished_at"]),
        "report_date": report_date,
        "qualified": not failure_reasons,
        "failure_reasons": failure_reasons,
        "sources": sources,
        "metrics": {
            "collected_items": sum(details["items"] for details in sources.values()),
            "normalized_items": int(((tasks.get("normalize_news_items") or {}).get("metrics") or {}).get("normalized_items") or 0),
            "deduped_items": deduped_items,
            "selected_items": selected_items,
            "duplicate_rate": _ratio(max(0, dedupe_input - deduped_items), dedupe_input),
            "selection_rate": _ratio(selected_items, deduped_items),
            "schema_pass_rate": _ratio(max(0, schema_total - schema_invalid), schema_total),
        },
        "gate": gate,
        "deep_review": review,
        "model_providers": model_providers,
        "model_calls": {key: value for key, value in model_calls.items() if key != "providers"},
        "human_queue": human_queue,
    }


def _source_results(conn: sqlite3.Connection, run_id: str, required_sources: list[str]) -> dict[str, dict[str, Any]]:
    results = {source: {"present": False, "items": 0, "errors": []} for source in required_sources}
    for row in conn.execute("SELECT source, item_count, payload_json FROM raw_artifacts WHERE run_id = ? AND domain = 'news'", (run_id,)).fetchall():
        source = str(row["source"])
        if source not in results:
            continue
        payload = repo.loads(row["payload_json"], {})
        results[source] = {"present": True, "items": int(row["item_count"] or 0), "errors": list(payload.get("errors") or [])}
    return results


def _model_call_metrics(conn: sqlite3.Connection, run_id: str) -> dict[str, Any]:
    rows = conn.execute(
        "SELECT status, provider, COUNT(*) AS count FROM model_calls WHERE run_id = ? GROUP BY status, provider",
        (run_id,),
    ).fetchall()
    metrics: dict[str, Any] = {"success": 0, "schema_invalid": 0, "failed": 0, "retryable_failure": 0, "providers": set()}
    for row in rows:
        status = str(row["status"])
        metrics[status] = int(metrics.get(status, 0)) + int(row["count"])
        metrics["providers"].add(str(row["provider"] or "unknown"))
    return metrics


def _human_queue_metrics(conn: sqlite3.Connection, run_id: str) -> dict[str, int]:
    metrics = {"pending": 0, "resolved": 0, "rejected": 0}
    for row in conn.execute("SELECT status, payload_json FROM human_queue_items WHERE domain = 'news'").fetchall():
        payload = repo.loads(row["payload_json"], {})
        if str(payload.get("run_id") or "") != run_id:
            continue
        status = str(row["status"])
        metrics[status] = metrics.get(status, 0) + 1
    return metrics


def _latest_health(conn: sqlite3.Connection, sources: list[str]) -> dict[str, dict[str, Any]]:
    result = {}
    for source in sources:
        row = conn.execute(
            "SELECT status, message, latency_ms, consecutive_failures, last_success_at, checked_at FROM source_health_checks WHERE domain = 'news' AND source = ? ORDER BY id DESC LIMIT 1",
            (source,),
        ).fetchone()
        result[source] = dict(row) if row else {"status": "not_checked", "message": "health probe has not run"}
    return result


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _percent(value: float | None) -> str:
    return "-" if value is None else f"{value * 100:.2f}%"
