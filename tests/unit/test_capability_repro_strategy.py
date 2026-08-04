from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import create_app
from ai4sec_platform.app.api import capabilities as capability_api
from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities.repro_strategy import resolve_repro_strategy


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "test.db")


def _client(settings: Settings, payload: dict, *, source_url: str = "https://github.com/example/repo") -> tuple[TestClient, int]:
    with connect(settings) as conn:
        init_db(conn)
        item_id = repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="Strategy example",
            source_url=source_url,
            payload=payload,
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


def test_strategy_prefers_only_verified_official_demo() -> None:
    verified = resolve_repro_strategy({"payload": {"demo_url": "https://demo.example", "demo_verified": True}})
    unverified = resolve_repro_strategy({"payload": {"demo_url": "https://demo.example", "is_web": True}})

    assert verified.strategy == "official_demo"
    assert verified.should_enqueue is False
    assert unverified.strategy == "local_web"


def test_strategy_marks_no_real_code_unsupported_and_allows_operator_override() -> None:
    item = {"payload": {"implementation_depth": {"has_real_code": False}}}

    assert resolve_repro_strategy(item).strategy == "unsupported"
    assert resolve_repro_strategy(item, "cli").strategy == "cli"


def test_start_repro_skips_verified_demo_without_creating_task(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, item_id = _client(settings, {
        "code_url": "https://github.com/example/repo",
        "demo_url": "https://demo.example",
        "demo_verified": True,
        "repro_strategy": "official_demo",
    })

    response = client.post(f"/api/capabilities/items/{item_id}/start-repro", json={"strategy": "auto"})

    assert response.status_code == 200
    assert response.json()["reason"] == "official_demo"
    with connect(settings) as conn:
        assert repo.list_repro_tasks(conn, item_id=item_id) == []


def test_start_repro_skips_explicitly_unsupported_item_without_repo(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, item_id = _client(
        settings,
        {"implementation_depth": {"has_real_code": False}},
        source_url="",
    )

    response = client.post(f"/api/capabilities/items/{item_id}/start-repro", json={"strategy": "auto"})

    assert response.status_code == 200
    assert response.json()["reason"] == "unsupported"


def test_start_repro_persists_local_web_strategy_and_reserved_port(monkeypatch, tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, item_id = _client(settings, {"code_url": "https://github.com/example/repo", "is_web": True})
    monkeypatch.setattr(capability_api, "_alloc_web_port", lambda _conn: 18123)

    repo_commit = "A" * 40
    response = client.post(
        f"/api/capabilities/items/{item_id}/start-repro",
        json={"strategy": "auto", "repo_commit": repo_commit},
    )

    assert response.status_code == 200
    assert response.json()["strategy"] == "local_web"
    with connect(settings) as conn:
        task = repo.list_repro_tasks(conn, item_id=item_id)[0]
    assert task["repro_strategy"] == "local_web"
    assert task["repo_commit"] == repo_commit.casefold()
    assert task["web_port"] == 18123
    listed = client.get("/api/capabilities/repro-runs")
    assert listed.status_code == 200
    assert listed.json()["items"][0]["id"] == task["id"]
    assert listed.json()["items"][0]["item_id"] == item_id
    assert listed.json()["items"][0]["repro_strategy"] == "local_web"
    assert listed.json()["items"][0]["repo_commit"] == repo_commit.casefold()


def test_start_repro_rejects_non_commit_ref(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, item_id = _client(settings, {"code_url": "https://github.com/example/repo"})

    response = client.post(
        f"/api/capabilities/items/{item_id}/start-repro",
        json={"strategy": "cli", "repo_commit": "main"},
    )

    assert response.status_code == 422


def test_start_repro_rejects_removed_web_boolean(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    client, item_id = _client(settings, {"code_url": "https://github.com/example/repo"})

    response = client.post(f"/api/capabilities/items/{item_id}/start-repro", json={"web": True})

    assert response.status_code == 422
