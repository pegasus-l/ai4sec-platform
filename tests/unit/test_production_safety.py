from __future__ import annotations

import sqlite3
import ssl

import pytest

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db, reset_domain
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector


def _create_run(conn: sqlite3.Connection, domain: str, run_id: str) -> None:
    repo.create_pipeline_run(
        conn,
        run_id=run_id,
        domain=domain,
        pipeline_name=f"{domain}.test",
        status="success",
        started_at="2026-07-28T00:00:00Z",
        finished_at="2026-07-28T00:01:00Z",
        production_writes=False,
        summary={},
    )
    repo.create_domain_item(
        conn,
        domain=domain,
        item_type="test",
        title=f"{domain} item",
        summary="",
        score=1,
        status="active",
        source="test",
        source_url="",
        primary_date="2026-07-28",
        tags=[],
        metrics={},
        payload={},
    )


def test_reset_domain_preserves_other_domains(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "reset.db")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    _create_run(conn, "news", "news-run")
    _create_run(conn, "threats", "threat-run")
    conn.commit()

    reset_domain(conn, "threats")

    assert conn.execute("SELECT COUNT(*) FROM pipeline_runs WHERE domain = 'threats'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM domain_items WHERE domain = 'threats'").fetchone()[0] == 0
    assert conn.execute("SELECT COUNT(*) FROM pipeline_runs WHERE domain = 'news'").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM domain_items WHERE domain = 'news'").fetchone()[0] == 1
    conn.close()


def test_reset_domain_rejects_unknown_domain(tmp_path) -> None:
    conn = sqlite3.connect(tmp_path / "reset.db")
    init_db(conn)
    with pytest.raises(ValueError, match="Unsupported domain reset"):
        reset_domain(conn, "unknown")
    conn.close()


def test_threat_text_fetch_uses_default_tls_verification(monkeypatch) -> None:
    calls: list[dict] = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self) -> bytes:
            return b"verified"

    def fake_urlopen(request, **kwargs):
        calls.append(kwargs)
        return Response()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    assert LiveJsonConnector().get_text("https://example.test") == "verified"
    assert calls[0]["timeout"] == 30
    assert isinstance(calls[0]["context"], ssl.SSLContext)


def test_threat_text_fetch_rejects_invalid_ca_bundle(monkeypatch) -> None:
    monkeypatch.setenv("AI4SEC_THREAT_CA_BUNDLE", "/missing/ai4sec-ca.pem")

    with pytest.raises(RuntimeError, match="Invalid AI4SEC_THREAT_CA_BUNDLE"):
        LiveJsonConnector().tls_context()
