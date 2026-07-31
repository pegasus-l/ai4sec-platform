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
from ai4sec_platform.domains.news import review_queue
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.registry import PipelineRegistry
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.pipelines.runner import PipelineRunner
from ai4sec_platform.pipelines.steps.news import GateNewsCandidatesStep, apply_news_daily_defaults, persist_news_source_records


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

    assert steps[0].transaction_mode == "checkpointed"
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


def test_news_daily_defaults_are_bounded_but_full_legacy_is_explicit() -> None:
    daily_params: dict = {}
    apply_news_daily_defaults("news.daily_pipeline", daily_params)
    assert daily_params == {"collection_profile": "daily", "review_limit_per_type": 20, "max_pages": 1, "max_results": 30}

    full_params = {"collection_profile": "full_legacy", "max_pages": 5, "max_results": 100, "review_limit_per_type": 50}
    apply_news_daily_defaults("news.daily_pipeline", full_params)
    assert full_params == {"collection_profile": "full_legacy", "max_pages": 5, "max_results": 100, "review_limit_per_type": 50}


def test_gate_and_deep_review_schema_validation_is_strict() -> None:
    tech_map = reviewer.AgentTechMap.load(PROJECT_ROOT)
    valid_path = tech_map.catalog()[0]
    valid_gate = {
        "decision": "pass",
        "map_relevance_score": 90,
        "potential_value_score": 80,
        "information_sufficiency": 0.9,
        "provisional_tech_paths": [valid_path],
        "match_evidence": ["input evidence"],
        "reason": "valid gate",
        "confidence": 0.9,
    }
    valid_review = {
        "score_breakdown": {field: 80 for field in ["map_relevance", "novelty", "technical_depth", "engineering_value", "reproducibility", "influence", "freshness"]},
        "tech_paths": [valid_path],
        "topic": valid_path["category"],
        "work_name": "SchemaGuard",
        "theme_descriptor": "用于验证模型结构的安全评审器",
        "summary_zh": "结构完整的模型评审输出。",
        "promo_line": "它用于验证模型输出结构。",
        "highlight_line": "避免不完整结果进入正式资讯。",
        "review_reason": "字段和技术路径均符合约束。",
        "confidence": 0.9,
    }

    assert reviewer._gate_schema_errors(valid_gate, tech_map) == []
    assert reviewer._review_schema_errors(valid_review, tech_map) == []
    assert reviewer._gate_schema_errors({"decision": "pass"}, tech_map)
    assert reviewer._review_schema_errors({"score_breakdown": {"map_relevance": 80}}, tech_map)


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


def test_source_persistence_normalizes_multi_request_metadata(tmp_path) -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    repo.create_pipeline_run(conn, run_id="source-metadata", domain="news", pipeline_name="news.daily_pipeline")
    context = PipelineContext(run_id="source-metadata", pipeline_name="news.daily_pipeline", domain="news", settings=settings(tmp_path), conn=conn, artifact_store=ArtifactStore(tmp_path / "output"))

    result = persist_news_source_records(context, [{"source": "github", "path": "connector:github", "mode": "shadow", "items": [], "errors": [], "metadata": [{"query": "topic:security"}]}])

    summary = repo.loads(conn.execute("SELECT summary_json FROM data_sources WHERE domain = 'news' AND name = 'github'").fetchone()["summary_json"], {})
    assert result.status == "success"
    assert summary["requests"] == [{"query": "topic:security"}]
    assert context.outputs["news_raw_sources"][0]["metadata"] == {"requests": [{"query": "topic:security"}]}


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
                        "information_sufficiency": 0.9,
                        "provisional_tech_paths": [valid_path],
                        "match_evidence": ["agent security"],
                        "reason": "relevant to the mapped security topic",
                        "confidence": 0.9,
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


def test_schema_invalid_outputs_are_deduplicated_and_human_reject_unblocks_resume(monkeypatch, tmp_path) -> None:
    calls = 0

    class InvalidSchemaRouter:
        def active_config(self, _profile: str) -> dict:
            return {"provider": "test", "model": "invalid-schema-model"}

        def complete_json(self, **_kwargs):
            nonlocal calls
            calls += 1
            return {"provider": "test", "result": {"decision": "pass"}}

    monkeypatch.setattr(reviewer, "LLMRouter", InvalidSchemaRouter)
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.news_schema", domain="news", steps=[NewsCandidatesStep(), GateNewsCandidatesStep()]))
    runner = PipelineRunner(settings=settings(tmp_path), registry=registry)

    first = runner.run("test.news_schema", run_id="schema-first")
    second = runner.run("test.news_schema", {"_resume_from_run_id": "schema-first"}, run_id="schema-second")

    assert first["status"] == "failed"
    assert second["status"] == "failed"
    with connect(settings(tmp_path)) as conn:
        rows = review_queue.list_items(conn)
        assert len(rows) == 2
        assert {row["payload"]["run_id"] for row in rows} == {"schema-second"}
        assert conn.execute("SELECT COUNT(*) FROM model_calls WHERE status = 'schema_invalid'").fetchone()[0] == 4
        for row in rows:
            review_queue.set_item_status(conn, int(row["id"]), "reject")
        conn.commit()

    resumed = runner.run("test.news_schema", {"_resume_from_run_id": "schema-second"}, run_id="schema-rejected")

    assert resumed["status"] == "success"
    assert calls == 4
    gate_metrics = resumed["summary"]["steps"][-1]["metrics"]
    assert gate_metrics["human_rejected"] == 2
    assert gate_metrics["model_calls"] == 0


def test_news_review_queue_api_rejects_schema_candidate() -> None:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    item_id = review_queue.queue_schema_failure(conn, stage="gate", item={"item_key": "paper:1", "title": "Invalid"}, request_key="request-1", run_id="run-1", prompt_version=reviewer.GATE_PROMPT_VERSION, errors=["missing fields"], fallback={"decision": "reject"})
    conn.commit()
    app.dependency_overrides[get_db] = lambda: conn
    try:
        listed = TestClient(app).get("/api/news/ops/review-queue")
        rejected = TestClient(app).post(f"/api/news/ops/review-queue/{item_id}", json={"action": "reject"})
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert listed.status_code == 200
    assert listed.json()["items"][0]["payload"]["item_key"] == "paper:1"
    assert rejected.status_code == 200
    assert rejected.json()["status"] == "rejected"


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
