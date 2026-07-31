from __future__ import annotations

from pathlib import Path

from ai4sec_platform.core.config import Settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.news import operations as news_operations
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
    with connect(settings) as conn:
        source = next(item for item in news_operations.source_status(conn) if item["id"] == "x")
    assert source["consecutive_failures"] == 0
    assert source["last_health_check"]["status"] == "disabled"


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


def test_health_history_tracks_failures_and_resets_after_success(monkeypatch, tmp_path: Path) -> None:
    outcomes = [
        SourceFetchResult(source_name="arxiv", connector_name="fake", errors=["HTTP 503"]),
        SourceFetchResult(source_name="arxiv", connector_name="fake", errors=["read timed out"]),
        SourceFetchResult(source_name="arxiv", connector_name="fake", items=[{"id": "ok"}]),
    ]

    class FakeConnector:
        def health_check(self, config):
            return SourceHealth(status="configured", message="configured")

        def fetch(self, request):
            return outcomes.pop(0)

    monkeypatch.setattr("ai4sec_platform.domains.news.health.SourceRegistry.get", lambda *_args: FakeConnector())
    settings = Settings(project_root=Path(__file__).resolve().parents[2], output_dir=tmp_path, database_path=tmp_path / "history.db")
    with connect(settings) as conn:
        init_db(conn)
        first = probe_news_sources(conn, settings, ["arxiv"])[0]
        second = probe_news_sources(conn, settings, ["arxiv"])[0]
        third = probe_news_sources(conn, settings, ["arxiv"])[0]
        rows = conn.execute("SELECT * FROM source_health_checks ORDER BY id").fetchall()

    assert first["consecutive_failures"] == 1
    assert second["consecutive_failures"] == 2
    assert third["consecutive_failures"] == 0
    assert third["last_success_at"] == third["checked_at"]
    assert [row["status"] for row in rows] == ["upstream_failed", "timeout", "healthy"]
