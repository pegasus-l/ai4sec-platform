from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass

from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import app
from ai4sec_platform.app.api import news as news_api
from ai4sec_platform.artifacts.store import ArtifactStore
from ai4sec_platform.core.config import PROJECT_ROOT, Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.news.pipelines import news_daily_pipeline
from ai4sec_platform.domains.news import reviewer
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.registry import PipelineRegistry
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.pipelines.runner import PipelineRunner
from ai4sec_platform.pipelines.steps.news import GateNewsCandidatesStep, persist_news_source_records


@dataclass
class NewsCandidatesStep:
    name: str = "prepare_news_candidates"
    step_type: str = "test"

    def run(self, context) -> StepResult:
        context.outputs["deduped_news_items"] = [
            {"item_key": "paper:a", "source_type": "paper", "title": "A", "summary": "agent security", "url": "https://example.com/a"},
            {"item_key": "paper:b", "source_type": "paper", "title": "B", "summary": "agent security", "url": "https://example.com/b"},
        ]
        return StepResult(metrics={"candidates": 2})


def settings(tmp_path) -> Settings:
    return Settings(project_root=PROJECT_ROOT, output_dir=tmp_path / "output", database_path=tmp_path / "platform.db")


def test_news_steps_declare_checkpoint_resume_inputs() -> None:
    steps = news_daily_pipeline().steps
    contracts = {step.name: tuple(getattr(step, "resume_input_keys", ())) for step in steps if getattr(step, "resume_safe", False)}

    assert contracts == {
        "extract_news_references": ("news_raw_sources",),
        "normalize_news_items": ("news_raw_sources",),
        "deduplicate_news_candidates": ("normalized_news_items",),
        "resolve_news_candidate_links": ("deduped_news_items",),
        "gate_news_candidates_with_tech_map": ("deduped_news_items",),
        "enrich_news_candidates_with_model": ("gated_news_items",),
        "build_news_items": ("reviewed_news_items",),
        "build_news_daily_report": ("news_item_ids", "news_items"),
        "audit_news_quality": ("news_items",),
    }


def test_source_errors_mark_live_collection_partial(tmp_path) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    repo.create_pipeline_run(conn, run_id="source-partial", domain="news", pipeline_name="news.daily_pipeline")
    context = PipelineContext(run_id="source-partial", pipeline_name="news.daily_pipeline", domain="news", settings=settings(tmp_path), conn=conn, artifact_store=ArtifactStore(tmp_path / "output"))

    result = persist_news_source_records(context, [{"source": "rss", "path": "connector:rss", "mode": "shadow", "items": [], "errors": ["upstream timeout"]}])

    assert result.status == "partial"
    assert result.metrics["errors"] == 1
    assert "retry failed sources separately" in result.message


def test_gate_retry_reuses_success_and_calls_only_failed_candidate(monkeypatch, tmp_path) -> None:
    calls = {"A": 0, "B": 0}
    lock = threading.Lock()
    valid_path = reviewer.AgentTechMap.load(PROJECT_ROOT).catalog()[0]

    class FakeRouter:
        def active_config(self, _profile: str) -> dict:
            return {"provider": "test", "model": "stable-model"}

        def complete_json(self, *, payload, **_kwargs):
            title = str(payload["candidate"]["title"])
            with lock:
                calls[title] += 1
                attempt = calls[title]
            if title == "B" and attempt <= reviewer.MODEL_MAX_ATTEMPTS:
                raise RuntimeError("HTTP Error 503: unavailable")
            return {
                "provider": "test",
                "result": {
                    "decision": "pass",
                    "map_relevance_score": 90,
                    "potential_value_score": 80,
                    "provisional_tech_paths": [valid_path],
                },
            }

    monkeypatch.setattr(reviewer, "LLMRouter", FakeRouter)
    monkeypatch.setattr(reviewer.time, "sleep", lambda *_args: None)
    monkeypatch.setattr(reviewer.random, "uniform", lambda *_args: 0.0)
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.news_retry", domain="news", steps=[NewsCandidatesStep(), GateNewsCandidatesStep()]))
    runner = PipelineRunner(settings=settings(tmp_path), registry=registry)

    failed = runner.run("test.news_retry", run_id="news-failed")
    resumed = runner.run("test.news_retry", {"_resume_from_run_id": "news-failed"}, run_id="news-resumed")

    assert failed["status"] == "failed"
    assert resumed["status"] == "success"
    assert resumed["summary"]["resumed_from_run_id"] == "news-failed"
    assert calls == {"A": 1, "B": 4}
    with connect(settings(tmp_path)) as conn:
        gate_task = conn.execute("SELECT metrics_json FROM task_runs WHERE run_id = 'news-resumed' AND step_name = 'gate_news_candidates_with_tech_map'").fetchone()
        metrics = repo.loads(gate_task["metrics_json"], {})
        assert metrics["cache_hits"] == 1
        assert metrics["model_calls"] == 1


def test_news_run_detail_exposes_checkpoint_retry_state() -> None:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    repo.create_pipeline_run(conn, run_id="failed-news", domain="news", pipeline_name="news.daily_pipeline", status="failed")
    repo.create_task_run(conn, run_id="failed-news", step_name="build_news_daily_report", status="failed", error_message="report failed")
    repo.create_artifact(conn, run_id="failed-news", artifact_type="pipeline_checkpoint", path="checkpoint.json")

    app.dependency_overrides[get_db] = lambda: conn
    try:
        response = TestClient(app).get("/api/news/ops/runs/failed-news")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert response.json()["retry"] == {"allowed": True, "stage": "build_news_daily_report", "mode": "checkpoint_resume"}


def test_source_retry_api_preserves_origin_date_and_parameters(monkeypatch) -> None:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    repo.create_pipeline_run(
        conn,
        run_id="source-origin",
        domain="news",
        pipeline_name="news.daily_pipeline",
        status="partial",
        summary={"params": {"date": "2026-07-29", "review_limit": 20, "reset": False}},
    )
    repo.create_data_source(
        conn,
        domain="news",
        name="rss",
        source_type="shadow",
        status="degraded",
        health="degraded",
        summary={"run_id": "source-origin", "errors": ["timeout"]},
    )
    captured = []
    monkeypatch.setattr(news_api, "start_run", lambda request: captured.append(request) or {"run_id": "source-retry", "status": "queued"})
    app.dependency_overrides[get_db] = lambda: conn
    try:
        response = TestClient(app).post("/api/news/ops/sources/rss/retry")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert response.json()["retry_of_run_id"] == "source-origin"
    assert captured[0].params == {"date": "2026-07-29", "review_limit": 20, "sources": ["rss"]}
