from __future__ import annotations

import sqlite3

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.news.acceptance import build_news_daily_acceptance, render_news_daily_acceptance_markdown


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    return conn


def test_three_distinct_real_model_cycles_pass_acceptance() -> None:
    conn = connection()
    for index, report_date in enumerate(["2026-07-29", "2026-07-30", "2026-07-31"], 1):
        _seed_cycle(conn, run_id=f"run-{index}", report_date=report_date)

    report = build_news_daily_acceptance(
        conn,
        required_sources=["arxiv", "github"],
        disabled_sources=["x"],
        required_cycles=3,
    )

    assert report["status"] == "pass"
    assert report["qualified_cycles"] == 3
    assert report["qualified_dates"] == ["2026-07-29", "2026-07-30", "2026-07-31"]
    assert report["ready_to_start_cycle"] is False
    assert report["model_ready"] is False
    assert report["cycles"][0]["metrics"]["duplicate_rate"] == 0.2
    assert report["cycles"][0]["metrics"]["selection_rate"] == 0.25
    assert "合格周期：`3/3`" in render_news_daily_acceptance_markdown(report)


def test_local_rules_and_failed_source_cannot_pass_acceptance() -> None:
    conn = connection()
    _seed_cycle(
        conn,
        run_id="run-local",
        report_date="2026-07-31",
        provider="local_rules",
        source_errors={"github": ["HTTP 429"]},
    )

    report = build_news_daily_acceptance(
        conn,
        required_sources=["arxiv", "github"],
        required_cycles=1,
    )

    assert report["status"] == "fail"
    assert report["qualified_cycles"] == 0
    assert "failed_sources=github" in report["cycles"][0]["failure_reasons"]
    assert "real_model_not_used" in report["cycles"][0]["failure_reasons"]


def test_same_business_date_only_counts_once() -> None:
    conn = connection()
    _seed_cycle(conn, run_id="run-first", report_date="2026-07-31")
    _seed_cycle(conn, run_id="run-retry", report_date="2026-07-31")

    report = build_news_daily_acceptance(
        conn,
        required_sources=["arxiv", "github"],
        run_ids=["run-first", "run-retry"],
        required_cycles=2,
    )

    assert report["status"] == "in_progress"
    assert report["qualified_runs"] == 2
    assert report["qualified_cycles"] == 1
    assert report["qualified_dates"] == ["2026-07-31"]
    assert report["remaining_cycles"] == 1


def test_default_selection_keeps_older_distinct_dates_after_retries() -> None:
    conn = connection()
    _seed_cycle(conn, run_id="run-day-one", report_date="2026-07-29")
    _seed_cycle(conn, run_id="run-day-two", report_date="2026-07-30")
    _seed_cycle(conn, run_id="run-day-three", report_date="2026-07-31")
    _seed_cycle(conn, run_id="run-day-three-retry", report_date="2026-07-31")

    report = build_news_daily_acceptance(
        conn,
        required_sources=["arxiv", "github"],
        required_cycles=3,
    )

    assert report["status"] == "pass"
    assert report["qualified_dates"] == ["2026-07-29", "2026-07-30", "2026-07-31"]


def test_explicit_missing_run_is_reported() -> None:
    conn = connection()
    _seed_cycle(conn, run_id="run-present", report_date="2026-07-31")

    report = build_news_daily_acceptance(
        conn,
        required_sources=["arxiv", "github"],
        run_ids=["run-present", "run-missing"],
        required_cycles=1,
    )

    assert report["status"] == "fail"
    assert report["missing_run_ids"] == ["run-missing"]


def _seed_cycle(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    report_date: str,
    provider: str = "dashscope",
    source_errors: dict[str, list[str]] | None = None,
) -> None:
    repo.create_pipeline_run(
        conn,
        run_id=run_id,
        domain="news",
        pipeline_name="news.daily_pipeline",
        status="success",
        started_at=f"{report_date}T00:00:00+00:00",
        finished_at=f"{report_date}T00:10:00+00:00",
        summary={"params": {"date": report_date}},
    )
    for source, count in {"arxiv": 6, "github": 4}.items():
        repo.create_raw_artifact(
            conn,
            run_id=run_id,
            domain="news",
            source=source,
            item_count=count,
            payload={"errors": (source_errors or {}).get(source, [])},
        )
    task_metrics = {
        "collect_news_sources": {"sources": 2, "items": 10, "errors": 0},
        "normalize_news_items": {"normalized_items": 10},
        "deduplicate_news_candidates": {"input_items": 10, "deduped_items": 8},
        "gate_news_candidates_with_tech_map": {"candidates": 8, "passed": 4, "schema_invalid": 0, "failed": 0},
        "enrich_news_candidates_with_model": {"candidates": 4, "selected": 2, "schema_invalid": 0, "failed": 0},
        "build_news_items": {"items": 2, "created": 2, "updated": 0},
        "build_news_daily_report": {"item_count": 2, "highlight_count": 2},
    }
    for step_name, metrics in task_metrics.items():
        repo.create_task_run(conn, run_id=run_id, step_name=step_name, status="success", metrics=metrics)
    for index, agent_name in enumerate(["news_tech_map_gate", "news_deep_review"], 1):
        repo.create_model_call(
            conn,
            run_id=run_id,
            agent_name=agent_name,
            model_profile="configured_model",
            provider=provider,
            request_key=f"{run_id}-{index}",
            status="success",
        )
    conn.commit()
