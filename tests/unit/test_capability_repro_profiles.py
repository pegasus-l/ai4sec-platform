from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
import pytest

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import create_app
from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities.adapters import repro_runner
from ai4sec_platform.domains.capabilities.adapters.repro_runner import ReproRunner
from ai4sec_platform.domains.capabilities.repro_jobs import claim_next_repro_task


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "test.db")


def _client(settings: Settings) -> tuple[TestClient, int]:
    with connect(settings) as conn:
        init_db(conn)
        item_id = repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="Nested project",
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
    return TestClient(app), item_id


def test_nested_profile_requires_risk_approval_before_egress_and_queue(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, item_id = _client(settings)
    started = client.post(
        f"/api/capabilities/items/{item_id}/start-repro",
        json={"execution_profile": "nested_docker", "external_domains": ["api.example.com"]},
    )

    assert started.status_code == 200
    payload = started.json()
    assert payload["status"] == "awaiting_profile_approval"
    assert payload["execution_profile"] == "nested_docker"
    task_id = int(payload["task_id"])
    request_id = int(payload["egress_requests"][0]["id"])
    with connect(settings) as conn:
        assert claim_next_repro_task(conn, worker_id="nested", task_id=task_id, execution_profile="nested_docker") is None

    missing_reason = client.post(
        f"/api/capabilities/repro/{task_id}/profile/approve",
        json={"reviewer": "security", "reason": ""},
    )
    approved_profile = client.post(
        f"/api/capabilities/repro/{task_id}/profile/approve",
        json={"reviewer": "security", "reason": "project compose file requires isolated nested Docker"},
    )

    assert missing_reason.status_code == 422
    assert missing_reason.json()["detail"]["code"] == "reason_required"
    assert approved_profile.status_code == 200
    assert approved_profile.json()["profile"]["task_status"] == "awaiting_egress_approval"
    monkeypatch.setattr(
        "ai4sec_platform.domains.capabilities.egress_approvals.PublicUrlPolicy.validate",
        lambda *_args, **_kwargs: None,
    )
    approved_egress = client.post(
        f"/api/capabilities/repro/{task_id}/egress/{request_id}/approve",
        json={"reviewer": "security", "reason": "required test endpoint"},
    )

    assert approved_egress.status_code == 200
    assert approved_egress.json()["task_status"] == "queued"
    with connect(settings) as conn:
        assert claim_next_repro_task(conn, worker_id="standard", task_id=task_id, execution_profile="standard") is None
        claimed = claim_next_repro_task(conn, worker_id="nested", task_id=task_id, execution_profile="nested_docker")
    assert claimed and claimed["profile_approval_status"] == "approved"


def test_nested_profile_rejection_stops_task(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, item_id = _client(settings)
    started = client.post(
        f"/api/capabilities/items/{item_id}/start-repro",
        json={"execution_profile": "nested_docker"},
    ).json()

    rejected = client.post(
        f"/api/capabilities/repro/{started['task_id']}/profile/reject",
        json={"reviewer": "security", "reason": "Docker is not required"},
    )

    assert rejected.status_code == 200
    assert rejected.json()["profile"]["task_status"] == "stopped"
    assert rejected.json()["profile"]["profile_approval_status"] == "rejected"


def test_standard_profile_command_drops_privileges(monkeypatch, tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("task-token", encoding="utf-8")
    token.chmod(0o600)
    monkeypatch.setattr(repro_runner, "REPRO_STANDARD_IMAGE", "standard:test")
    runner = ReproRunner(
        1,
        "https://github.com/example/repo",
        model_token_path=token,
        execution_profile="standard",
    )

    command = runner.build_run_command()

    assert "--read-only" in command
    assert command[command.index("--cap-drop") + 1] == "ALL"
    assert "--user" not in command
    assert "--runtime" not in command
    assert command[-1] == "standard:test"


def test_nested_profile_command_uses_sysbox(monkeypatch, tmp_path: Path) -> None:
    token = tmp_path / "token"
    token.write_text("task-token", encoding="utf-8")
    token.chmod(0o600)
    monkeypatch.setattr(repro_runner, "REPRO_IMAGE", "nested:test")
    monkeypatch.setattr(repro_runner, "REPRO_RUNTIME", "sysbox-runc")
    runner = ReproRunner(
        2,
        "https://github.com/example/repo",
        model_token_path=token,
        execution_profile="nested_docker",
    )

    command = runner.build_run_command()

    assert command[command.index("--runtime") + 1] == "sysbox-runc"
    assert "--read-only" not in command
    assert command[-1] == "nested:test"


def test_standard_profile_preflight_rejects_rootful_docker(monkeypatch) -> None:
    monkeypatch.setattr(repro_runner, "REPRO_LLM_BASE_URL", "https://gateway.example/api/model-gateway/v1")

    class Result:
        returncode = 0
        stdout = '["name=seccomp,profile=builtin"]'

    monkeypatch.setattr(repro_runner, "_safe_run", lambda *_args, **_kwargs: Result())

    with pytest.raises(RuntimeError, match="requires a rootless Docker daemon"):
        repro_runner.validate_repro_runtime_config(
            check_image=True,
            require_token=False,
            execution_profile="standard",
        )


def test_standard_profile_stays_disabled_without_rootless_egress_adapter(monkeypatch) -> None:
    monkeypatch.setattr(repro_runner, "REPRO_LLM_BASE_URL", "https://gateway.example/api/model-gateway/v1")

    class Result:
        returncode = 0
        stdout = '["name=rootless"]'

    monkeypatch.setattr(repro_runner, "_safe_run", lambda *_args, **_kwargs: Result())

    with pytest.raises(RuntimeError, match="rootless egress enforcement adapter"):
        repro_runner.validate_repro_runtime_config(
            check_image=True,
            require_token=False,
            execution_profile="standard",
        )
