from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import create_app
from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities import repro_worker as worker_module
from ai4sec_platform.domains.capabilities.repro_jobs import (
    claim_next_repro_task,
    reconcile_interrupted_repro_tasks,
    request_repro_cleanup,
    request_repro_stop,
)
from ai4sec_platform.domains.capabilities.repro_worker import CapabilityReproWorker
from ai4sec_platform.pipelines.jobs import set_execution_kill_switch


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "test.db")


def _allow_test_runtime(monkeypatch) -> None:
    monkeypatch.setattr(worker_module, "validate_repro_runtime_config", lambda **_kwargs: Path("/test/token"))


def _create_task(settings: Settings, *, status: str = "queued") -> int:
    with connect(settings) as conn:
        init_db(conn)
        item_id = repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="Example",
            source_url="https://github.com/example/repo",
            payload={"code_url": "https://github.com/example/repo"},
        )
        task_id = repo.create_repro_task(conn, item_id=item_id, repo_url="https://github.com/example/repo")
        if status != "queued":
            repo.update_repro_task(conn, task_id=task_id, status=status)
        conn.commit()
        return task_id


def test_claim_and_stop_requests_are_persistent(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    queued_task = _create_task(settings)
    running_task = _create_task(settings)

    with connect(settings) as conn:
        claimed = claim_next_repro_task(conn, worker_id="worker-1", task_id=running_task)
        assert claimed and claimed["status"] == "running"
        assert claimed["worker_id"] == "worker-1"
        assert request_repro_stop(conn, queued_task) == "stopped"
        assert request_repro_stop(conn, running_task) == "cancelling"
        conn.commit()
        queued = repo.get_repro_task(conn, queued_task)
        running = repo.get_repro_task(conn, running_task)

    assert queued and queued["status"] == "stopped"
    assert running and running["status"] == "running"
    assert running["cancel_requested"] == 1


def test_recovery_marks_running_task_failed(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings)

    with connect(settings) as conn:
        claim_next_repro_task(conn, worker_id="dead-worker", task_id=task_id)
        interrupted = reconcile_interrupted_repro_tasks(conn)
        task = repo.get_repro_task(conn, task_id)

    assert [row["id"] for row in interrupted] == [task_id]
    assert task and task["status"] == "failed"
    assert "not replayed automatically" in task["result"]


def test_recovery_requeues_interrupted_cleanup(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings, status="failed")

    with connect(settings) as conn:
        repo.update_repro_task(conn, task_id=task_id, cleanup_requested=2)
        conn.commit()
        assert reconcile_interrupted_repro_tasks(conn) == []
        task = repo.get_repro_task(conn, task_id)

    assert task and task["cleanup_requested"] == 1


def test_worker_executes_claimed_task_without_api_thread(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings)
    _allow_test_runtime(monkeypatch)

    class FakeRunner:
        def __init__(self, task_id, repo_url, on_log, on_status, web_port, should_stop, on_heartbeat):
            self.task_id = task_id
            self.on_log = on_log
            self.on_status = on_status
            self.on_heartbeat = on_heartbeat
            self.container_name = f"fake-{task_id}"
            self.workspace = tmp_path / f"task-{task_id}"

        def run(self) -> None:
            self.on_log("worker log")
            self.on_heartbeat()
            self.on_status("success", result="done")

    monkeypatch.setattr(worker_module, "ReproRunner", FakeRunner)

    result = CapabilityReproWorker(settings, worker_id="worker-1").run_once(task_id=task_id)

    assert result and result["status"] == "success"
    with connect(settings) as conn:
        task = repo.get_repro_task(conn, task_id)
    assert task and task["container_name"] == f"fake-{task_id}"
    assert "worker log" in task["log"]


def test_platform_kill_switch_stops_queued_repro_task(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings)

    with connect(settings) as conn:
        result = set_execution_kill_switch(conn, enabled=True, reason="emergency")
        task = repo.get_repro_task(conn, task_id)

    assert result["stopped_queued_repro_tasks"] == 1
    assert task and task["status"] == "stopped"
    assert bool(task["cancel_requested"]) is True
    with connect(settings) as conn:
        assert claim_next_repro_task(conn, worker_id="blocked-worker", task_id=task_id) is None


def test_worker_records_runner_crash_and_keeps_serving(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings)
    _allow_test_runtime(monkeypatch)

    class CrashingRunner:
        def __init__(self, task_id, repo_url, **_kwargs):
            self.container_name = f"crash-{task_id}"
            self.workspace = tmp_path / f"task-{task_id}"

        def run(self) -> None:
            raise RuntimeError("planned crash")

    monkeypatch.setattr(worker_module, "ReproRunner", CrashingRunner)

    result = CapabilityReproWorker(settings).run_once(task_id=task_id)

    assert result and result["status"] == "failed"
    assert "planned crash" in result["result"]


def test_cleanup_is_queued_and_executed_by_worker(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings, status="failed")
    _allow_test_runtime(monkeypatch)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with connect(settings) as conn:
        repo.update_repro_task(conn, task_id=task_id, container_name="old-container", workspace_path=str(workspace))
        assert request_repro_cleanup(conn, task_id) == "cleanup_queued"
        conn.commit()

    commands: list[list[str]] = []
    monkeypatch.setattr(worker_module, "_safe_run", lambda command, **_kwargs: commands.append(command))

    result = CapabilityReproWorker(settings).run_once(task_id=task_id)

    assert result == {"task_id": task_id, "status": "cleaned"}
    assert commands == [["docker", "rm", "-f", "old-container"]]
    assert not workspace.exists()


def test_start_api_only_queues_task(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with connect(settings) as conn:
        init_db(conn)
        item_id = repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="Example",
            source_url="https://github.com/example/repo",
            payload={"code_url": "https://github.com/example/repo"},
        )
        conn.commit()

    app = create_app()

    def override_db():
        with connect(settings) as conn:
            init_db(conn)
            yield conn
            conn.commit()

    app.dependency_overrides[get_db] = override_db
    response = TestClient(app).post(f"/api/capabilities/items/{item_id}/start-repro", json={"web": False})

    assert response.status_code == 200
    assert response.json()["status"] == "queued"
    with connect(settings) as conn:
        tasks = repo.list_repro_tasks(conn, item_id=item_id)
    assert len(tasks) == 1
    assert tasks[0]["status"] == "queued"
    assert tasks[0]["worker_id"] == ""

    duplicate = TestClient(app).post(f"/api/capabilities/items/{item_id}/start-repro", json={"web": False})
    assert duplicate.status_code == 409
