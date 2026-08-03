from __future__ import annotations

from pathlib import Path
import socket

from fastapi.testclient import TestClient
import pytest

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import create_app
from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities import egress_approvals
from ai4sec_platform.domains.capabilities.egress_approvals import (
    ReproEgressApprovalError,
    approved_egress_domains,
    create_egress_requests,
    normalize_requested_domains,
    review_egress_request,
)
from ai4sec_platform.domains.capabilities.repro_jobs import claim_next_repro_task
from ai4sec_platform.domains.capabilities.repro_policy import enqueue_repro_task


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "test.db")


def _create_waiting_task(settings: Settings, *, domains: tuple[str, ...] = ("api.example.com",)) -> tuple[int, list[dict]]:
    with connect(settings) as conn:
        init_db(conn)
        item_id = repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="External API reproduction",
            source_url="https://github.com/example/repo",
            payload={"code_url": "https://github.com/example/repo"},
        )
        task_id = enqueue_repro_task(
            conn,
            item_id=item_id,
            repo_url="https://github.com/example/repo",
            trigger="manual",
            initial_status="awaiting_egress_approval",
        )
        requests = create_egress_requests(
            conn,
            task_id=task_id,
            domains=domains,
            purpose="download test fixture",
            requested_by="tester",
        )
        conn.commit()
    return task_id, requests


@pytest.mark.parametrize(
    "domain",
    ["*.example.com", "https://example.com", "example.com:443", "127.0.0.1", "localhost", "example.com/path"],
)
def test_requested_egress_domain_requires_exact_hostname(domain: str) -> None:
    with pytest.raises(ReproEgressApprovalError, match="domain|IP addresses"):
        normalize_requested_domains([domain])


def test_all_egress_requests_must_be_approved_before_queueing(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    task_id, requests = _create_waiting_task(settings, domains=("api.example.com", "cdn.example.com"))

    with connect(settings) as conn:
        assert claim_next_repro_task(conn, worker_id="worker", task_id=task_id) is None
        review_egress_request(
            conn,
            task_id=task_id,
            request_id=int(requests[0]["id"]),
            decision="approved",
            reviewed_by="reviewer",
            reason="required by upstream project",
            resolver=_public_resolver,
        )
        assert repo.get_repro_task(conn, task_id)["status"] == "awaiting_egress_approval"
        review_egress_request(
            conn,
            task_id=task_id,
            request_id=int(requests[1]["id"]),
            decision="approved",
            reviewed_by="reviewer",
            reason="required by upstream project",
            resolver=_public_resolver,
        )
        assert approved_egress_domains(conn, task_id=task_id) == ("api.example.com", "cdn.example.com")
        conn.commit()
        claimed = claim_next_repro_task(conn, worker_id="worker", task_id=task_id)

    assert claimed and claimed["status"] == "running"


def test_rejected_or_private_egress_never_reaches_worker(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    private_task, private_requests = _create_waiting_task(settings)

    with connect(settings) as conn:
        with pytest.raises(ReproEgressApprovalError, match="unsafe or unavailable"):
            review_egress_request(
                conn,
                task_id=private_task,
                request_id=int(private_requests[0]["id"]),
                decision="approved",
                reviewed_by="reviewer",
                reason="",
                resolver=_private_resolver,
            )
        assert repo.get_repro_task(conn, private_task)["status"] == "awaiting_egress_approval"
        review_egress_request(
            conn,
            task_id=private_task,
            request_id=int(private_requests[0]["id"]),
            decision="rejected",
            reviewed_by="reviewer",
            reason="unnecessary external access",
        )
        assert repo.get_repro_task(conn, private_task)["status"] == "stopped"
        conn.commit()
        assert claim_next_repro_task(conn, worker_id="worker", task_id=private_task) is None


def test_egress_approval_api_persists_audit_and_releases_task(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with connect(settings) as conn:
        init_db(conn)
        item_id = repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="API approval",
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
    monkeypatch.setattr(egress_approvals.PublicUrlPolicy, "validate", lambda *_args, **_kwargs: None)
    client = TestClient(app)

    started = client.post(
        f"/api/capabilities/items/{item_id}/start-repro",
        json={
            "external_domains": ["API.Example.com", "api.example.com"],
            "egress_purpose": "call project test API",
            "requested_by": "developer",
        },
    )

    assert started.status_code == 200
    payload = started.json()
    assert payload["status"] == "awaiting_egress_approval"
    assert len(payload["egress_requests"]) == 1
    task_id = int(payload["task_id"])
    request_id = int(payload["egress_requests"][0]["id"])
    with connect(settings) as conn:
        assert claim_next_repro_task(conn, worker_id="worker", task_id=task_id) is None

    approved = client.post(
        f"/api/capabilities/repro/{task_id}/egress/{request_id}/approve",
        json={"reviewer": "security-operator", "reason": "verified project dependency"},
    )
    audit = client.get(f"/api/capabilities/repro/{task_id}/egress")

    assert approved.status_code == 200
    assert approved.json()["task_status"] == "queued"
    assert audit.status_code == 200
    assert audit.json()["items"][0]["reviewed_by"] == "security-operator"
    assert audit.json()["items"][0]["review_reason"] == "verified project dependency"


def _public_resolver(host, port, *, type=socket.SOCK_STREAM):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port))]


def _private_resolver(host, port, *, type=socket.SOCK_STREAM):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
