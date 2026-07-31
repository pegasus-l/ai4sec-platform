from __future__ import annotations

from pathlib import Path

from ai4sec_platform.core.config import Settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.news.health import classify_health_error, probe_news_sources
from ai4sec_platform.sources.result import SourceFetchResult
from ai4sec_platform.schemas.sources import SourceHealth


def test_health_error_classification() -> None:
    assert classify_health_error("HTTP Error 401: Unauthorized") == "auth_failed"
    assert classify_health_error("HTTP 402 Payment Required") == "quota_exhausted"
    assert classify_health_error("HTTP 429 rate limit") == "rate_limited"
    assert classify_health_error("upstream HTTP 503") == "upstream_failed"
    assert classify_health_error("read timed out") == "timeout"


def test_disabled_source_health_is_persisted_without_network(tmp_path: Path) -> None:
    settings = Settings(project_root=Path(__file__).resolve().parents[2], output_dir=tmp_path, database_path=tmp_path / "health.db")
    with connect(settings) as conn:
        init_db(conn)
        results = probe_news_sources(conn, settings, ["x"])
        row = conn.execute("SELECT status, health, summary_json FROM data_sources WHERE domain = 'news' AND name = 'x'").fetchone()

    assert results[0]["status"] == "disabled"
    assert row["status"] == "disabled"
    assert "disabled" in row["summary_json"]


def test_health_probe_records_success(monkeypatch, tmp_path: Path) -> None:
    class FakeConnector:
        def health_check(self, config):
            return SourceHealth(status="configured", message="configured")

        def fetch(self, request):
            return SourceFetchResult(source_name=request.source_name, connector_name="fake", items=[{"id": "one"}])

    monkeypatch.setattr("ai4sec_platform.domains.news.health.SourceRegistry.get", lambda *_args: FakeConnector())
    settings = Settings(project_root=Path(__file__).resolve().parents[2], output_dir=tmp_path, database_path=tmp_path / "health.db")
    with connect(settings) as conn:
        init_db(conn)
        results = probe_news_sources(conn, settings, ["arxiv"], timeout_seconds=2)

    assert results[0]["status"] == "healthy"
    assert results[0]["items"] == 1
