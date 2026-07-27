from __future__ import annotations

import threading
import time
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


@dataclass
class InspectProgressStep:
    seen_current_step: list[str]
    name: str = "inspect_progress"
    step_type: str = "test"

    def run(self, context) -> StepResult:
        row = context.conn.execute("SELECT summary_json FROM pipeline_runs WHERE run_id = ?", (context.run_id,)).fetchone()
        self.seen_current_step.append(repo.loads(row["summary_json"])["current_step"])
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


def test_async_run_returns_pollable_run_id(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setenv("AI4SEC_DATABASE_PATH", str(tmp_path / "async.db"))
    monkeypatch.setenv("AI4SEC_OUTPUT_DIR", str(tmp_path / "output"))
    started = threading.Event()
    release = threading.Event()

    class FakeRunner:
        def run(self, pipeline_name, params, *, run_id):
            started.set()
            release.wait(timeout=5)
            settings = load_settings()
            with connect(settings) as conn:
                init_db(conn)
                repo.create_pipeline_run(
                    conn,
                    run_id=run_id,
                    domain="vulnerabilities",
                    pipeline_name=pipeline_name,
                    status="success",
                    finished_at="done",
                    summary={"steps": [], "completed_steps": 1, "total_steps": 1, "current_step": "", "status": "success"},
                )
                conn.commit()
            return {"run_id": run_id, "pipeline_name": pipeline_name, "domain": "vulnerabilities", "status": "success", "summary": {}}

    monkeypatch.setattr(runs_api, "PipelineRunner", FakeRunner)
    with runs_api._active_runs_lock:
        runs_api._active_runs.clear()
    client = TestClient(app)

    response = client.post("/api/runs", json={"pipeline_name": "vulnerabilities.event_aggregation_pipeline", "wait": False})
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["run_id"].startswith("run_")
    assert payload["poll_url"] == f"/api/runs/{payload['run_id']}"
    assert started.wait(timeout=2)

    detail = client.get(payload["poll_url"])
    assert detail.status_code == 200
    assert detail.json()["run_id"] == payload["run_id"]
    assert detail.json()["status"] in {"queued", "running"}

    release.set()
    deadline = time.time() + 5
    while time.time() < deadline:
        detail_payload = client.get(payload["poll_url"]).json()
        if detail_payload["status"] == "success":
            break
        time.sleep(0.01)
    assert detail_payload["status"] == "success"
    assert detail_payload["progress"] == {"completed_steps": 1, "total_steps": 1, "current_step": ""}


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
