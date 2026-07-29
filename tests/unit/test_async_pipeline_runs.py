from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from fastapi.testclient import TestClient

from ai4sec_platform.app.api import runs as runs_api
from ai4sec_platform.app.main import app
from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.registry import PipelineRegistry
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.pipelines.runner import PipelineRunner
from ai4sec_platform.pipelines.worker import PipelineWorker


@dataclass
class InspectProgressStep:
    seen_current_step: list[str]
    name: str = "inspect_progress"
    step_type: str = "test"

    def run(self, context) -> StepResult:
        row = context.conn.execute("SELECT summary_json FROM pipeline_runs WHERE run_id = ?", (context.run_id,)).fetchone()
        self.seen_current_step.append(repo.loads(row["summary_json"])["current_step"])
        return StepResult(metrics={"items": 1})


@dataclass
class RetryApprovedStep:
    name: str
    step_type: str = "test"
    resume_safe: bool = True
    resume_input_keys: tuple[str, ...] = ()

    def run(self, context) -> StepResult:
        return StepResult(metrics={"items": 1})


@dataclass
class RetryUnsafeStep:
    name: str
    step_type: str = "test"

    def run(self, context) -> StepResult:
        return StepResult(metrics={"items": 1})


def test_runner_reuses_reserved_run_id_and_records_progress(tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "test.db")
    seen_current_step: list[str] = []
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.progress", domain="vulnerabilities", steps=[InspectProgressStep(seen_current_step)]))

    result = PipelineRunner(settings=settings, registry=registry).run("test.progress", run_id="run_reserved")

    assert result["run_id"] == "run_reserved"
    assert seen_current_step == ["inspect_progress"]
    with connect(settings) as conn:
        row = repo.row_to_dict(conn.execute("SELECT * FROM pipeline_runs WHERE run_id = ?", ("run_reserved",)).fetchone())
        assert row["status"] == "success"
        assert row["summary"]["completed_steps"] == 1
        assert row["summary"]["total_steps"] == 1
        assert row["summary"]["current_step"] == ""


def test_queued_run_is_pollable_and_executed_by_worker(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AI4SEC_DATABASE_PATH", str(tmp_path / "async.db"))
    monkeypatch.setenv("AI4SEC_OUTPUT_DIR", str(tmp_path / "output"))
    client = TestClient(app)

    response = client.post("/api/runs", json={"pipeline_name": "vulnerabilities.event_aggregation_pipeline"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["run_id"].startswith("run_")
    assert payload["poll_url"] == f"/api/runs/{payload['run_id']}"

    detail = client.get(payload["poll_url"])
    assert detail.status_code == 200
    assert detail.json()["run_id"] == payload["run_id"]
    assert detail.json()["status"] == "queued"
    assert detail.json()["job"]["status"] == "queued"

    result = PipelineWorker().run_once(run_id=payload["run_id"])
    assert result is not None
    detail_payload = client.get(payload["poll_url"]).json()
    assert detail_payload["status"] == "success"
    assert detail_payload["job"]["status"] == "success"
    history = client.get("/api/vulnerabilities/runs")
    assert history.status_code == 200
    assert history.json()["items"][0]["run_id"] == payload["run_id"]


def test_queued_run_can_be_cancelled_through_api(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AI4SEC_DATABASE_PATH", str(tmp_path / "cancel.db"))
    monkeypatch.setenv("AI4SEC_OUTPUT_DIR", str(tmp_path / "output"))
    client = TestClient(app)
    response = client.post("/api/runs", json={"pipeline_name": "vulnerabilities.event_aggregation_pipeline"})
    run_id = response.json()["run_id"]

    cancelled = client.post(f"/api/runs/{run_id}/cancel")
    detail = client.get(f"/api/runs/{run_id}")

    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"
    assert detail.json()["status"] == "cancelled"
    assert detail.json()["job"]["status"] == "cancelled"


def test_run_api_rejects_removed_synchronous_wait_field() -> None:
    response = TestClient(app).post(
        "/api/runs",
        json={"pipeline_name": "vulnerabilities.event_aggregation_pipeline", "wait": True},
    )

    assert response.status_code == 422


def test_failed_run_retry_api_uses_verified_checkpoint_mode(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AI4SEC_DATABASE_PATH", str(tmp_path / "retry.db"))
    monkeypatch.setenv("AI4SEC_OUTPUT_DIR", str(tmp_path / "output"))
    settings = load_settings()
    checkpoint_path = tmp_path / "checkpoint.json"
    checkpoint_path.write_text(
        '{"completed_steps":[],"next_step":{"name":"aggregate","resume_safe":true,"resume_input_keys":[]}}',
        encoding="utf-8",
    )
    registry = PipelineRegistry()
    registry.register(
        PipelineDefinition(
            name="vulnerabilities.event_aggregation_pipeline",
            domain="vulnerabilities",
            steps=[RetryApprovedStep("aggregate")],
        )
    )
    monkeypatch.setattr(runs_api, "default_registry", lambda: registry)
    with connect(settings) as conn:
        init_db(conn)
        repo.create_pipeline_run(
            conn,
            run_id="run_failed",
            domain="vulnerabilities",
            pipeline_name="vulnerabilities.event_aggregation_pipeline",
            status="failed",
            summary={
                "params": {"limit": 20, "reset": True},
                "steps": [{"name": "aggregate", "status": "failed"}],
            },
        )
        repo.create_artifact(
            conn,
            run_id="run_failed",
            artifact_type="pipeline_checkpoint",
            path=str(checkpoint_path),
        )
        conn.commit()
    captured: list[runs_api.RunPipelineRequest] = []

    def fake_start_run(request):
        captured.append(request)
        return {"run_id": "run_retry", "status": "queued"}

    monkeypatch.setattr(runs_api, "start_run", fake_start_run)
    response = TestClient(app).post("/api/runs/run_failed/retry")

    assert response.status_code == 200
    assert response.json()["run_id"] == "run_retry"
    assert captured[0].reset is False
    assert captured[0].params == {"limit": 20, "_resume_from_run_id": "run_failed"}


def test_failed_run_retry_api_rejects_stale_checkpoint(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AI4SEC_DATABASE_PATH", str(tmp_path / "retry-stale.db"))
    monkeypatch.setenv("AI4SEC_OUTPUT_DIR", str(tmp_path / "output"))
    settings = load_settings()
    checkpoint_path = tmp_path / "stale-checkpoint.json"
    checkpoint_path.write_text(
        '{"completed_steps":[],"next_step":{"name":"safe_prepare","resume_safe":true,"resume_input_keys":[]}}',
        encoding="utf-8",
    )
    registry = PipelineRegistry()
    registry.register(
        PipelineDefinition(
            name="test.stale_retry",
            domain="vulnerabilities",
            steps=[RetryApprovedStep("safe_prepare"), RetryUnsafeStep("unsafe_model")],
        )
    )
    monkeypatch.setattr(runs_api, "default_registry", lambda: registry)
    with connect(settings) as conn:
        init_db(conn)
        repo.create_pipeline_run(
            conn,
            run_id="run_stale",
            domain="vulnerabilities",
            pipeline_name="test.stale_retry",
            status="failed",
            summary={
                "params": {},
                "steps": [
                    {"name": "safe_prepare", "status": "success"},
                    {"name": "unsafe_model", "status": "failed"},
                ],
            },
        )
        repo.create_artifact(
            conn,
            run_id="run_stale",
            artifact_type="pipeline_checkpoint",
            path=str(checkpoint_path),
        )
        conn.commit()

    response = TestClient(app).post("/api/runs/run_stale/retry")

    assert response.status_code == 409
    assert "Checkpoint is stale" in response.json()["detail"]


def test_vulnerability_run_results_are_scoped_by_run_id(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AI4SEC_DATABASE_PATH", str(tmp_path / "results.db"))
    monkeypatch.setenv("AI4SEC_OUTPUT_DIR", str(tmp_path / "output"))
    settings = load_settings()
    with connect(settings) as conn:
        init_db(conn)
        repo.create_domain_item(
            conn,
            domain="vulnerabilities",
            item_type="material",
            title="current run material",
            metrics={"pipeline_run": "run_current"},
        )
        repo.create_domain_item(
            conn,
            domain="vulnerabilities",
            item_type="material",
            title="history material",
            metrics={"pipeline_run": "run_history"},
        )
        conn.commit()

    client = TestClient(app)
    response = client.get("/api/vulnerabilities/runs/run_current/results")

    assert response.status_code == 200
    payload = response.json()
    assert payload["count"] == 1
    assert [item["title"] for item in payload["stages"]["material"]] == ["current run material"]
    profiles = client.get("/api/vulnerabilities/keyword-profiles")
    assert profiles.status_code == 200
    assert any(item["name"] == "smoke" for item in profiles.json()["items"])
