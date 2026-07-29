from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from ai4sec_platform.core.config import Settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.jobs import JobConflictError, claim_next_job, enqueue_job, get_job
from ai4sec_platform.pipelines.registry import PipelineRegistry
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.pipelines.worker import PipelineWorker, WorkerAlreadyRunningError


@dataclass
class SuccessfulStep:
    name: str = "successful_step"
    step_type: str = "test"

    def run(self, context) -> StepResult:
        return StepResult(metrics={"items": 1})


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "platform.db")


def _registry() -> PipelineRegistry:
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.persisted", domain="news", steps=[SuccessfulStep()]))
    return registry


def _enqueue(settings: Settings, run_id: str, *, reset: bool = False) -> None:
    with connect(settings) as conn:
        init_db(conn)
        enqueue_job(
            conn,
            run_id=run_id,
            domain="news",
            pipeline_name="test.persisted",
            params={"reset": reset},
            total_steps=1,
            reset_requested=reset,
        )


def test_worker_executes_persisted_job_and_records_attempt(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _enqueue(settings, "run_persisted")

    result = PipelineWorker(settings=settings, registry=_registry(), worker_id="worker-test").run_once()

    assert result is not None
    assert result["status"] == "success"
    with connect(settings) as conn:
        job = get_job(conn, "run_persisted")
    assert job["status"] == "success"
    assert job["attempt_count"] == 1
    assert job["worker_id"] == "worker-test"


def test_worker_marks_interrupted_job_failed_until_safe_resume_exists(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _enqueue(settings, "run_interrupted")
    with connect(settings) as conn:
        claimed = claim_next_job(conn, worker_id="dead-worker")
    assert claimed is not None
    assert claimed["status"] == "running"

    recovered = PipelineWorker(settings=settings, registry=_registry()).recover()

    assert recovered == ["run_interrupted"]
    with connect(settings) as conn:
        job = get_job(conn, "run_interrupted")
        run_status = conn.execute("SELECT status FROM pipeline_runs WHERE run_id = ?", ("run_interrupted",)).fetchone()[0]
    assert job["status"] == "failed"
    assert job["error_message"] == "worker interrupted; manual retry required"
    assert run_status == "failed"


def test_reset_job_survives_domain_reset_and_finishes(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _enqueue(settings, "run_reset", reset=True)

    result = PipelineWorker(settings=settings, registry=_registry()).run_once(run_id="run_reset")

    assert result is not None
    with connect(settings) as conn:
        assert get_job(conn, "run_reset")["status"] == "success"


def test_persistent_queue_rejects_duplicate_and_reset_conflicts(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _enqueue(settings, "run_first")

    with pytest.raises(JobConflictError, match="already queued or running"):
        _enqueue(settings, "run_duplicate")
    with pytest.raises(JobConflictError, match="reset run cannot start"):
        _enqueue(settings, "run_reset", reset=True)


def test_single_host_worker_lock_rejects_second_worker(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    first = PipelineWorker(settings=settings, registry=_registry())
    second = PipelineWorker(settings=settings, registry=_registry())

    with first._worker_lock():
        with pytest.raises(WorkerAlreadyRunningError):
            with second._worker_lock():
                pass
