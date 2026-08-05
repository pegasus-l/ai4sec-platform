from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import create_app
from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities.model_gateway import (
    authorize_task_model_call,
    issue_task_model_token,
    reconcile_task_model_usage,
    revoke_task_model_tokens,
)


def test_task_model_token_enforces_model_calls_tokens_and_revocation() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    task_id = _create_task(conn)
    token = issue_task_model_token(conn, task_id=task_id, model="glm-5.2", ttl_seconds=300, max_calls=2, max_tokens=1000)

    assert authorize_task_model_call(conn, token=token, model="other", requested_tokens=10) is None
    assert authorize_task_model_call(conn, token=token, model="glm-5.2", requested_tokens=600)
    token_row = conn.execute("SELECT id FROM repro_model_tokens WHERE task_id = ?", (task_id,)).fetchone()
    reconcile_task_model_usage(conn, token_id=token_row["id"], reserved_tokens=600, actual_tokens=60)
    assert authorize_task_model_call(conn, token=token, model="glm-5.2", requested_tokens=950) is None
    assert authorize_task_model_call(conn, token=token, model="glm-5.2", requested_tokens=400)
    assert authorize_task_model_call(conn, token=token, model="glm-5.2", requested_tokens=1) is None

    revoke_task_model_tokens(conn, task_id=task_id)
    assert authorize_task_model_call(conn, token=token, model="glm-5.2", requested_tokens=1) is None
    stored = conn.execute("SELECT token_hash FROM repro_model_tokens WHERE task_id = ?", (task_id,)).fetchone()
    assert stored["token_hash"] != token


def test_model_gateway_replaces_model_and_provider_key(monkeypatch, tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "gateway.db")
    with connect(settings) as conn:
        init_db(conn)
        task_id = _create_task(conn)
        token = issue_task_model_token(conn, task_id=task_id, model="glm-5.2", ttl_seconds=300, max_calls=2, max_tokens=10_000)
        conn.commit()

    observed = {}

    class FakeResponse:
        ok = True
        status_code = 200
        headers = {"content-type": "application/json"}

        def json(self):
            return {"choices": [{"message": {"content": "ok"}}], "usage": {"total_tokens": 12}}

    def fake_post(url, *, headers, json, timeout, stream):
        observed.update(url=url, headers=headers, payload=json, timeout=timeout, stream=stream)
        return FakeResponse()

    monkeypatch.setattr("ai4sec_platform.app.api.model_gateway.requests.post", fake_post)
    monkeypatch.setattr(
        "ai4sec_platform.app.api.model_gateway.LLMRouter._configured_model",
        lambda *_args: SimpleNamespace(base_url="https://provider.example/v1", api_key="provider-secret", model="upstream-glm", timeout_seconds=30),
    )
    app = create_app(settings)

    def override_db():
        with connect(settings) as conn:
            init_db(conn)
            yield conn

    app.dependency_overrides[get_db] = override_db
    response = TestClient(app).post(
        "/api/model-gateway/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "glm-5.2", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 100},
    )

    assert response.status_code == 200
    assert observed["payload"]["model"] == "upstream-glm"
    assert observed["headers"]["Authorization"] == "Bearer provider-secret"
    assert "provider-secret" not in response.text
    with connect(settings) as conn:
        usage = conn.execute("SELECT calls_used, tokens_used FROM repro_model_tokens WHERE task_id = ?", (task_id,)).fetchone()
    assert dict(usage) == {"calls_used": 1, "tokens_used": 12}
    rejected = TestClient(app).post(
        "/api/model-gateway/v1/chat/completions",
        headers={"Authorization": "Bearer invalid"},
        json={"model": "glm-5.2", "messages": []},
    )
    assert rejected.status_code == 401


def test_streaming_model_gateway_reconciles_reported_usage(monkeypatch, tmp_path: Path) -> None:
    settings = Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "gateway.db")
    with connect(settings) as conn:
        init_db(conn)
        task_id = _create_task(conn)
        token = issue_task_model_token(conn, task_id=task_id, model="glm-5.2", ttl_seconds=300, max_calls=2, max_tokens=10_000)
        conn.commit()

    class FakeResponse:
        ok = True
        status_code = 200
        headers = {"content-type": "text/event-stream"}

        def iter_lines(self):
            yield b'data: {"choices":[{"delta":{"content":"ok"}}]}'
            yield b'data: {"choices":[],"usage":{"total_tokens":23}}'
            yield b"data: [DONE]"

        def close(self):
            return None

    observed = {}

    def fake_post(_url, *, headers, json, timeout, stream):
        observed.update(payload=json, stream=stream)
        return FakeResponse()

    monkeypatch.setattr("ai4sec_platform.app.api.model_gateway.requests.post", fake_post)
    monkeypatch.setattr(
        "ai4sec_platform.app.api.model_gateway.LLMRouter._configured_model",
        lambda *_args: SimpleNamespace(base_url="https://provider.example/v1", api_key="provider-secret", model="upstream-glm", timeout_seconds=30),
    )
    app = create_app(settings)

    def override_db():
        with connect(settings) as conn:
            init_db(conn)
            yield conn

    app.dependency_overrides[get_db] = override_db
    response = TestClient(app).post(
        "/api/model-gateway/v1/chat/completions",
        headers={"Authorization": f"Bearer {token}"},
        json={"model": "glm-5.2", "messages": [{"role": "user", "content": "hello"}], "max_tokens": 100, "stream": True},
    )

    assert response.status_code == 200
    assert observed["stream"] is True
    assert observed["payload"]["stream_options"] == {"include_usage": True}
    with connect(settings) as conn:
        usage = conn.execute("SELECT calls_used, tokens_used FROM repro_model_tokens WHERE task_id = ?", (task_id,)).fetchone()
    assert dict(usage) == {"calls_used": 1, "tokens_used": 23}


def _create_task(conn: sqlite3.Connection) -> int:
    item_id = repo.create_domain_item(conn, domain="capabilities", item_type="capability", title="Gateway test")
    return repo.create_repro_task(conn, item_id=item_id, repo_url="https://github.com/example/repo")
