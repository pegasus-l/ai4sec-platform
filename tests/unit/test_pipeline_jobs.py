from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import threading
import time

import pytest

from ai4sec_platform.core.config import Settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.jobs import JobConflictError, claim_next_job, enqueue_job, get_job, request_job_cancel
from ai4sec_platform.pipelines.registry import PipelineRegistry
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.pipelines.runner import PipelineRunner
from ai4sec_platform.pipelines.worker import PipelineWorker, WorkerAlreadyRunningError


@dataclass
class SuccessfulStep:
    name: str = "successful_step"
    step_type: str = "test"

    def run(self, context) -> StepResult:
        return StepResult(metrics={"items": 1})


@dataclass
class BlockingStep:
    started: threading.Event
    release: threading.Event
    name: str = "blocking_step"
    step_type: str = "test"

    def run(self, context) -> StepResult:
        self.started.set()
        self.release.wait(timeout=5)
        return StepResult(metrics={"items": 1})


@dataclass
class CheckpointSourceStep:
    calls: list[str]
    name: str = "checkpoint_source"
    step_type: str = "test"

    def run(self, context) -> StepResult:
        self.calls.append(self.name)
        context.outputs["checkpoint_value"] = {"value": "persisted"}
        return StepResult(metrics={"items": 1})


@dataclass
class CheckpointConsumerStep:
    calls: list[str]
    fail: bool = True
    name: str = "checkpoint_consumer"
    step_type: str = "test"
    resume_safe: bool = True
    resume_input_keys: tuple[str, ...] = ("checkpoint_value",)

    def run(self, context) -> StepResult:
        self.calls.append(self.name)
        assert context.outputs["checkpoint_value"] == {"value": "persisted"}
        if self.fail:
            raise RuntimeError("planned failure")
        return StepResult(metrics={"items": 1})


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "platform.db")


def _registry() -> PipelineRegistry:
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.persisted", domain="news", steps=[SuccessfulStep()]))
    return registry


def _blocking_registry(started: threading.Event, release: threading.Event) -> PipelineRegistry:
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.persisted", domain="news", steps=[BlockingStep(started, release)]))
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


def test_queued_job_can_be_cancelled_without_execution(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _enqueue(settings, "run_queued_cancel")

    with connect(settings) as conn:
        result = request_job_cancel(conn, "run_queued_cancel")
        job = get_job(conn, "run_queued_cancel")
        run_status = conn.execute("SELECT status FROM pipeline_runs WHERE run_id = ?", ("run_queued_cancel",)).fetchone()[0]

    assert result["status"] == "cancelled"
    assert job["status"] == "cancelled"
    assert job["cancel_requested"] is True
    assert run_status == "cancelled"
    assert PipelineWorker(settings=settings, registry=_registry()).run_once() is None


def test_running_job_heartbeats_and_cancels_at_step_boundary(tmp_path: Path, monkeypatch) -> None:
    settings = _settings(tmp_path)
    _enqueue(settings, "run_running_cancel")
    started = threading.Event()
    release = threading.Event()
    worker = PipelineWorker(settings=settings, registry=_blocking_registry(started, release), heartbeat_interval=0.05)
    heartbeat_calls: list[str] = []
    original_heartbeat = worker._heartbeat

    def recording_heartbeat(run_id: str) -> bool:
        heartbeat_calls.append(run_id)
        return original_heartbeat(run_id)

    monkeypatch.setattr(worker, "_heartbeat", recording_heartbeat)
    results: list[dict | None] = []
    thread = threading.Thread(target=lambda: results.append(worker.run_once()))
    thread.start()
    assert started.wait(timeout=2)
    deadline = time.time() + 2
    while not heartbeat_calls and time.time() < deadline:
        time.sleep(0.01)

    with connect(settings) as conn:
        cancel_result = request_job_cancel(conn, "run_running_cancel")
    release.set()
    thread.join(timeout=5)

    assert cancel_result["status"] == "cancellation_requested"
    assert heartbeat_calls
    assert results[0] is not None
    assert results[0]["status"] == "cancelled"
    with connect(settings) as conn:
        job = get_job(conn, "run_running_cancel")
    assert job["status"] == "cancelled"


def test_runner_resumes_from_verified_checkpoint_without_replaying_completed_step(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    calls: list[str] = []
    source = CheckpointSourceStep(calls)
    consumer = CheckpointConsumerStep(calls)
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.checkpoint", domain="news", steps=[source, consumer]))
    runner = PipelineRunner(settings=settings, registry=registry)

    failed = runner.run("test.checkpoint", run_id="run_failed")
    consumer.fail = False
    resumed = runner.run("test.checkpoint", {"_resume_from_run_id": "run_failed"}, run_id="run_resumed")

    assert failed["status"] == "failed"
    assert resumed["status"] == "success"
    assert calls == ["checkpoint_source", "checkpoint_consumer", "checkpoint_consumer"]
    assert resumed["summary"]["resumed_from_run_id"] == "run_failed"
    with connect(settings) as conn:
        restored = conn.execute(
            "SELECT status FROM task_runs WHERE run_id = ? AND step_name = ?", ("run_resumed", "checkpoint_source")
        ).fetchone()[0]
    assert restored == "restored"


def test_runner_rejects_checkpoint_when_semantic_inputs_change(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    calls: list[str] = []
    source = CheckpointSourceStep(calls)
    consumer = CheckpointConsumerStep(calls)
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.checkpoint", domain="news", steps=[source, consumer]))
    runner = PipelineRunner(settings=settings, registry=registry)

    runner.run("test.checkpoint", {"limit": 1}, run_id="run_failed")

    with pytest.raises(ValueError, match="Checkpoint does not match"):
        runner.run("test.checkpoint", {"limit": 2, "_resume_from_run_id": "run_failed"}, run_id="run_mismatch")


def test_runner_rejects_resume_for_step_without_explicit_safety_approval(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    calls: list[str] = []
    source = CheckpointSourceStep(calls)
    consumer = CheckpointConsumerStep(calls, resume_safe=False)
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.checkpoint", domain="news", steps=[source, consumer]))
    runner = PipelineRunner(settings=settings, registry=registry)

    runner.run("test.checkpoint", run_id="run_unsafe")

    with pytest.raises(ValueError, match="No recoverable checkpoint"):
        runner.run("test.checkpoint", {"_resume_from_run_id": "run_unsafe"}, run_id="run_rejected")
