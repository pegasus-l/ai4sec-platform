from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import create_app
from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities import repro_worker as worker_module
from ai4sec_platform.domains.capabilities import repro_policy
from ai4sec_platform.domains.capabilities.repro_jobs import (
    ReproStateTransitionError,
    claim_next_repro_task,
    reconcile_interrupted_repro_tasks,
    register_repro_worker,
    request_repro_cleanup,
    request_repro_stop,
    transition_repro_task,
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


def test_repro_state_machine_rejects_invalid_transition(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings)

    with connect(settings) as conn:
        try:
            transition_repro_task(conn, task_id=task_id, status="success")
        except ReproStateTransitionError as exc:
            assert "queued -> success" in str(exc)
        else:
            raise AssertionError("invalid transition was accepted")


def test_recovery_accepts_completed_report_and_schedules_cleanup(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings)
    report = {
        "status": "success",
        "summary": "core workflow verified",
        "evidence": ["command exited successfully"],
        "limitations": [],
    }
    with connect(settings) as conn:
        claim_next_repro_task(conn, worker_id="dead-worker", task_id=task_id)
        repo.update_repro_task(
            conn,
            task_id=task_id,
            log=f"some output\n```json\n{__import__('json').dumps(report)}\n```",
        )
        conn.commit()

    monkeypatch.setattr(worker_module, "_safe_run", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(CapabilityReproWorker, "_cleanup_resources", lambda *_args: None)
    recovered = CapabilityReproWorker(settings).recover()

    assert recovered == [task_id]
    with connect(settings) as conn:
        task = repo.get_repro_task(conn, task_id)
    assert task and task["status"] == "success"
    assert task["cleanup_requested"] == 1
    assert "recovered completed report" in task["result"]


def test_worker_executes_claimed_task_without_api_thread(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings)
    with connect(settings) as conn:
        now = "2026-01-01T00:00:00Z"
        conn.execute(
            """
            INSERT INTO capability_repro_egress_domains
                (task_id, domain, purpose, status, requested_by, reviewed_by, created_at, reviewed_at, updated_at)
            VALUES (?, 'api.example.com', 'test API', 'approved', 'developer', 'reviewer', ?, ?, ?)
            """,
            (task_id, now, now, now),
        )
        conn.commit()
    _allow_test_runtime(monkeypatch)
    observed_current_tasks: list[int | None] = []
    observed_token_paths: list[Path] = []
    observed_config_paths: list[Path] = []

    class FakeRunner:
        def __init__(
            self,
            task_id,
            repo_url,
            on_log,
            on_status,
            web_port,
            should_stop,
            on_heartbeat,
            model_token_path,
            approved_egress_domains,
            execution_profile,
            managed_config_path,
            runtime_owner_id,
            on_runtime,
        ):
            self.task_id = task_id
            self.model_token_path = model_token_path
            self.on_log = on_log
            self.on_status = on_status
            self.on_heartbeat = on_heartbeat
            self.managed_config_path = managed_config_path
            self.runtime_owner_id = runtime_owner_id
            self.on_runtime = on_runtime
            assert approved_egress_domains == ("api.example.com",)
            assert execution_profile == "standard"
            assert len(runtime_owner_id) == 24
            self.container_name = f"fake-{task_id}"
            self.workspace = tmp_path / f"task-{task_id}"

        def run(self) -> None:
            observed_token_paths.append(self.model_token_path)
            observed_config_paths.append(self.managed_config_path)
            assert self.model_token_path.read_text(encoding="utf-8").startswith("rmt_")
            assert self.model_token_path.stat().st_mode & 0o077 == 0
            managed_config = json.loads(self.managed_config_path.read_text(encoding="utf-8"))
            assert self.managed_config_path.stat().st_mode & 0o077 == 0
            assert managed_config["permission"]["bash"]["docker *"] == "deny"
            assert managed_config["agent"]["build"]["permission"]["*"] == "deny"
            with connect(settings) as conn:
                worker = conn.execute(
                    "SELECT current_task_id FROM capability_repro_workers WHERE worker_id = 'worker-1'"
                ).fetchone()
                observed_current_tasks.append(worker["current_task_id"])
            self.on_log("worker log")
            self.on_runtime(container_id="a" * 64)
            self.on_heartbeat()
            self.on_status("success", result="done")

    monkeypatch.setattr(worker_module, "ReproRunner", FakeRunner)

    result = CapabilityReproWorker(settings, worker_id="worker-1").run_once(task_id=task_id)

    assert result and result["status"] == "success", result and result["result"]
    with connect(settings) as conn:
        task = repo.get_repro_task(conn, task_id)
        worker = conn.execute(
            "SELECT * FROM capability_repro_workers WHERE worker_id = 'worker-1'"
        ).fetchone()
        token = conn.execute("SELECT revoked_at FROM repro_model_tokens WHERE task_id = ?", (task_id,)).fetchone()
    assert task and task["container_name"] == f"fake-{task_id}"
    assert task["container_id"] == "a" * 64
    assert len(task["runtime_owner_id"]) == 24
    assert "worker log" in task["log"]
    assert observed_current_tasks == [task_id]
    assert observed_token_paths and not observed_token_paths[0].exists()
    assert observed_config_paths and not observed_config_paths[0].exists()
    assert worker and worker["status"] == "stopped"
    assert worker["current_task_id"] is None
    assert token and token["revoked_at"]


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
    worker = CapabilityReproWorker(settings)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    with connect(settings) as conn:
        repo.update_repro_task(
            conn,
            task_id=task_id,
            container_name="managed-container",
            container_id="a" * 64,
            workspace_path=str(workspace),
            runtime_owner_id=worker.runtime_owner_id,
        )
        assert request_repro_cleanup(conn, task_id) == "cleanup_queued"
        conn.commit()

    commands: list[list[str]] = []
    monkeypatch.setattr(worker_module, "_safe_run", lambda command, **_kwargs: commands.append(command))
    monkeypatch.setattr(worker_module, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(
        CapabilityReproWorker,
        "_inspect_container",
        staticmethod(lambda _container_ref: {
            "Id": "a" * 64,
            "Name": "/managed-container",
            "Config": {"Labels": {
                worker_module.REPRO_DOCKER_LABEL_RESOURCE: worker_module.REPRO_DOCKER_RESOURCE,
                worker_module.REPRO_DOCKER_LABEL_OWNER: worker.runtime_owner_id,
                worker_module.REPRO_DOCKER_LABEL_TASK: str(task_id),
                worker_module.REPRO_DOCKER_LABEL_PROFILE: "standard",
            }},
        }),
    )

    result = worker.run_once(task_id=task_id)

    assert result == {"task_id": task_id, "status": "cleaned"}
    assert commands == [["docker", "rm", "-f", "a" * 64]]
    assert not workspace.exists()


def test_cleanup_refuses_unlabelled_container_and_workspace_outside_root(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings, status="failed")
    worker = CapabilityReproWorker(settings)
    outside_workspace = tmp_path.parent / "outside-repro-workspace"
    outside_workspace.mkdir(exist_ok=True)
    task = {
        "id": task_id,
        "container_name": "legacy-container",
        "container_id": "b" * 64,
        "runtime_owner_id": worker.runtime_owner_id,
        "workspace_path": str(outside_workspace),
        "proxy_pid": 0,
    }
    commands: list[list[str]] = []
    monkeypatch.setattr(worker_module, "WORKSPACE_ROOT", tmp_path)
    monkeypatch.setattr(worker_module, "_safe_run", lambda command, **_kwargs: commands.append(command))
    monkeypatch.setattr(
        CapabilityReproWorker,
        "_inspect_container",
        staticmethod(lambda _container_ref: {"Id": "b" * 64, "Name": "/legacy-container", "Config": {"Labels": {}}}),
    )

    worker._cleanup_resources(task)

    assert commands == []
    assert outside_workspace.exists()
    outside_workspace.rmdir()


def test_recovery_removes_only_unknown_container_for_current_runtime_owner(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings, status="failed")
    worker = CapabilityReproWorker(settings)
    current_id = "c" * 64
    orphan_id = "d" * 64
    with connect(settings) as conn:
        repo.update_repro_task(
            conn,
            task_id=task_id,
            container_name="current-container",
            container_id=current_id,
            runtime_owner_id=worker.runtime_owner_id,
        )
        conn.commit()

    class Result:
        returncode = 0
        stdout = f"{current_id}\n{orphan_id}\n"

    removed_commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        if command[:3] == ["docker", "rm", "-f"]:
            removed_commands.append(command)
        return Result()

    def inspect_container(container_ref: str):
        is_current = container_ref == current_id
        return {
            "Id": container_ref,
            "Name": "/current-container" if is_current else "/orphan-container",
            "Config": {"Labels": {
                worker_module.REPRO_DOCKER_LABEL_RESOURCE: worker_module.REPRO_DOCKER_RESOURCE,
                worker_module.REPRO_DOCKER_LABEL_OWNER: worker.runtime_owner_id,
                worker_module.REPRO_DOCKER_LABEL_TASK: str(task_id if is_current else 999),
                worker_module.REPRO_DOCKER_LABEL_PROFILE: "standard",
            }},
        }

    monkeypatch.setattr(worker_module, "_safe_run", fake_run)
    monkeypatch.setattr(CapabilityReproWorker, "_inspect_container", staticmethod(inspect_container))

    removed = worker._reconcile_managed_orphans()

    assert removed == [orphan_id]
    assert removed_commands == [["docker", "rm", "-f", orphan_id]]


def test_persisted_proxy_stop_requires_expected_loopback_listener(monkeypatch) -> None:
    killed: list[tuple[int, int]] = []
    monkeypatch.setattr(
        Path,
        "read_bytes",
        lambda self: b"socat\0TCP-LISTEN:18080,bind=127.0.0.1,fork,reuseaddr\0",
    )
    monkeypatch.setattr(worker_module.os, "kill", lambda pid, sig: killed.append((pid, sig)))

    CapabilityReproWorker._stop_persisted_proxy({"proxy_pid": 4321, "web_port": 18080})
    CapabilityReproWorker._stop_persisted_proxy({"proxy_pid": 4322, "web_port": 18081})

    assert killed == [(4321, worker_module.signal.SIGTERM)]


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


def test_repro_stop_and_cleanup_apis_persist_requests(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings)
    app = create_app()

    def override_db():
        with connect(settings) as conn:
            init_db(conn)
            yield conn
            conn.commit()

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)

    stopped = client.post(f"/api/capabilities/repro/{task_id}/stop")
    cleanup = client.post(f"/api/capabilities/repro/{task_id}/cleanup")

    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"
    assert cleanup.status_code == 200
    assert cleanup.json()["status"] == "cleanup_queued"
    with connect(settings) as conn:
        task = repo.get_repro_task(conn, task_id)
    assert task and task["status"] == "stopped"
    assert task["cancel_requested"] == 1
    assert task["cleanup_requested"] == 1


def test_repro_sse_stream_uses_request_database_and_closes_on_terminal_task(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id = _create_task(settings, status="failed")
    with connect(settings) as conn:
        repo.update_repro_task(
            conn,
            task_id=task_id,
            log="✓ cloned\n✗ verification failed\n",
            report_json="invalid-json",
        )
        conn.commit()
    app = create_app()

    def override_db():
        with connect(settings) as conn:
            init_db(conn)
            yield conn

    app.dependency_overrides[get_db] = override_db
    response = TestClient(app).get(f"/api/capabilities/repro/{task_id}/logs/stream")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.text.count("event: log") == 2
    assert '"status": "failed", "report": null' in response.text
    assert response.text.endswith("event: end\ndata: {}\n\n")


def test_repro_limits_api_reports_configured_limits_and_usage(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _create_task(settings)
    app = create_app()

    def override_db():
        with connect(settings) as conn:
            init_db(conn)
            yield conn

    app.dependency_overrides[get_db] = override_db
    response = TestClient(app).get("/api/capabilities/repro-limits")

    assert response.status_code == 200
    assert response.json()["limits"] == {
        "max_concurrent_tasks": 1,
        "max_queued_tasks": 20,
        "max_attempts_per_item_24h": 3,
        "max_automatic_retries": 0,
        "worker_heartbeat_seconds": 10,
    }
    assert response.json()["usage"]["queued"] == 1
    assert response.json()["resources"]["cpus"] == 2.0
    assert response.json()["resources"]["log_max_bytes"] == 5 * 1024 * 1024


def test_repro_worker_status_reports_healthy_and_stale_workers(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with connect(settings) as conn:
        init_db(conn)
        register_repro_worker(
            conn,
            worker_id="repro-health-worker",
            hostname="test-host",
            pid=123,
            metadata={"kind": "capability_repro"},
        )
    app = create_app()

    def override_db():
        with connect(settings) as conn:
            init_db(conn)
            yield conn
            conn.commit()

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)

    healthy = client.get("/api/capabilities/repro-worker-status")
    assert healthy.status_code == 200
    assert healthy.json()["status"] == "ready"
    assert healthy.json()["workers"][0]["status"] == "healthy"

    with connect(settings) as conn:
        conn.execute(
            "UPDATE capability_repro_workers SET heartbeat_at = '2000-01-01T00:00:00Z' "
            "WHERE worker_id = 'repro-health-worker'"
        )
        conn.commit()
    stale = client.get("/api/capabilities/repro-worker-status")
    assert stale.json()["status"] == "unavailable"
    assert stale.json()["workers"][0]["status"] == "stale"


def test_start_repro_rejects_when_global_queue_is_full(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    _create_task(settings)
    monkeypatch.setattr(repro_policy, "REPRO_MAX_QUEUED_TASKS", 1)
    with connect(settings) as conn:
        item_id = repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="Second",
            source_url="https://github.com/example/second",
            payload={"code_url": "https://github.com/example/second"},
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

    assert response.status_code == 429
    assert response.json()["detail"]["code"] == "queue_full"


def test_start_repro_rejects_item_attempt_limit(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    monkeypatch.setattr(repro_policy, "REPRO_MAX_ATTEMPTS_PER_ITEM_24H", 2)
    first_task = _create_task(settings, status="failed")
    with connect(settings) as conn:
        item_id = int(repo.get_repro_task(conn, first_task)["item_id"])
        second_task = repo.create_repro_task(conn, item_id=item_id, repo_url="https://github.com/example/repo")
        repo.update_repro_task(conn, task_id=second_task, status="failed")
        conn.commit()
    app = create_app()

    def override_db():
        with connect(settings) as conn:
            init_db(conn)
            yield conn
            conn.commit()

    app.dependency_overrides[get_db] = override_db
    response = TestClient(app).post(f"/api/capabilities/items/{item_id}/start-repro", json={"web": False})

    assert response.status_code == 429
    assert response.json()["detail"]["code"] == "item_attempt_limit"


def test_capability_ops_endpoints_read_persisted_state(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with connect(settings) as conn:
        init_db(conn)
        repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="Audited capability",
            payload={"capability_type": "验证与评估"},
        )
        conn.commit()

    app = create_app()

    def override_db():
        with connect(settings) as conn:
            init_db(conn)
            yield conn

    app.dependency_overrides[get_db] = override_db
    client = TestClient(app)

    overview = client.get("/api/capabilities/ops/overview")
    failures = client.get("/api/capabilities/ops/repro-failures")
    missing_fields = client.get("/api/capabilities/ops/missing-fields")

    assert overview.status_code == 200
    assert overview.json()["stats"]["total"] == 1
    assert failures.status_code == 200
    assert missing_fields.status_code == 200
    assert missing_fields.json()["total_audited"] == 1
