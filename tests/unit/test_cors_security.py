from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai4sec_platform.app.main import create_app
from ai4sec_platform.core.config import Settings, load_settings


def _settings(tmp_path: Path, origins: list[str]) -> Settings:
    return Settings(
        project_root=tmp_path,
        output_dir=tmp_path / "output",
        database_path=tmp_path / "test.db",
        cors_allowed_origins=origins,
    )


def test_same_origin_default_does_not_emit_cors_headers(tmp_path: Path) -> None:
    response = TestClient(create_app(_settings(tmp_path, []))).get(
        "/api/health",
        headers={"Origin": "https://untrusted.example"},
    )

    assert response.status_code == 200
    assert "access-control-allow-origin" not in response.headers


def test_configured_origin_receives_cors_headers(tmp_path: Path) -> None:
    client = TestClient(create_app(_settings(tmp_path, ["https://console.example"])))

    response = client.get("/api/health", headers={"Origin": "https://console.example"})
    preflight = client.options(
        "/api/runs",
        headers={
            "Origin": "https://console.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert response.headers["access-control-allow-origin"] == "https://console.example"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert preflight.status_code == 200
    assert preflight.headers["access-control-allow-origin"] == "https://console.example"
    assert "POST" in preflight.headers["access-control-allow-methods"]


def test_untrusted_origin_is_not_allowed(tmp_path: Path) -> None:
    response = TestClient(create_app(_settings(tmp_path, ["https://console.example"]))).options(
        "/api/runs",
        headers={
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "POST",
        },
    )

    assert response.status_code == 400
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize(
    "value",
    [
        "*",
        "https://console.example/path",
        "https://console.example?admin=true",
        "https://user:password@console.example",
        "https://console.example:not-a-port",
        "file:///tmp/frontend",
    ],
)
def test_invalid_cors_origins_fail_configuration(monkeypatch, value: str) -> None:
    monkeypatch.setenv("AI4SEC_CORS_ALLOWED_ORIGINS", value)

    with pytest.raises(ValueError, match="CORS"):
        load_settings()


def test_cors_origins_are_normalized_and_deduplicated(monkeypatch) -> None:
    monkeypatch.setenv(
        "AI4SEC_CORS_ALLOWED_ORIGINS",
        " https://Console.Example/,http://127.0.0.1:5173,https://console.example ",
    )

    settings = load_settings()

    assert settings.cors_allowed_origins == ["https://console.example", "http://127.0.0.1:5173"]


def test_project_env_file_loads_cors_without_overriding_process_env(monkeypatch, tmp_path: Path) -> None:
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "app.yaml").write_text("app:\n  cors_allowed_origins: []\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "AI4SEC_CORS_ALLOWED_ORIGINS=https://file.example\nAI4SEC_SQLITE_SYNCHRONOUS=OFF\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("AI4SEC_CORS_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("AI4SEC_SQLITE_SYNCHRONOUS", "FULL")

    settings = load_settings(tmp_path)

    assert settings.cors_allowed_origins == ["https://file.example"]
    assert settings.sqlite_synchronous == "FULL"
