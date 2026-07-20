from __future__ import annotations

from ai4sec_platform.domains.threats.adapters import huawei_sources
from ai4sec_platform.pipelines.steps.threat_raw import ImportHuaweiRawStep, NormalizeHuaweiRawStep, BuildHuaweiThreatItemsStep
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.artifacts.store import ArtifactStore
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.sources.registry import SourceRegistry
from ai4sec_platform.schemas.sources import SourceFetchRequest
import sqlite3


def test_threat_connectors_build_live_requests() -> None:
    connector = SourceRegistry().get("gitcode")
    url = connector.build_url(SourceFetchRequest(source_name="gitcode:test", params={"resource": "repos", "org": "openharmony", "page": 1, "per_page": 10}))
    assert "orgs/openharmony/repos" in url
    assert "per_page=10" in url


def test_huawei_sources_live_mode_can_feed_existing_pipeline(monkeypatch, tmp_path) -> None:
    def fake_live(params):
        return [
            {
                "source": "repos",
                "path": "live:repos",
                "exists": True,
                "items": [
                    {
                        "name": "kernel_parser",
                        "url": "https://gitcode.com/openharmony/kernel_parser",
                        "description": "kernel parser security permission CVE-2024-12345",
                        "star_count": 99,
                        "org": "openharmony",
                    }
                ],
                "raw": {"projects": []},
                "mode": "live",
            },
            {"source": "cve_findings", "path": "generated:huawei_cve_scout", "exists": True, "items": [], "raw": {"orgs": {}}, "mode": "generated"},
        ]

    monkeypatch.setattr(huawei_sources, "load_huawei_live", fake_live)
    settings = load_settings()
    settings = settings.model_copy(update={"output_dir": tmp_path})
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    repo.create_pipeline_run(conn, run_id="live_test", domain="threats", pipeline_name="test.live")
    context = PipelineContext(run_id="live_test", pipeline_name="test.live", domain="threats", settings=settings, conn=conn, artifact_store=ArtifactStore(tmp_path), params={"mode": "live", "limit": 10})

    import_result = ImportHuaweiRawStep().run(context)
    NormalizeHuaweiRawStep().run(context)
    build_result = BuildHuaweiThreatItemsStep().run(context)

    assert import_result.metrics["sources"] >= 1
    assert build_result.metrics["items"] >= 1
    item = conn.execute("SELECT * FROM domain_items WHERE domain = 'threats' AND item_type = 'target'").fetchone()
    assert item is not None


def test_huawei_source_records_can_resume_downstream_pipeline(monkeypatch, tmp_path) -> None:
    records = [
        {
            "source": "repos",
            "path": "connector:test/repos",
            "exists": True,
            "items": [{"name": "kernel_parser", "url": "https://gitcode.com/openharmony/kernel_parser", "description": "kernel parser security", "star_count": 10, "org": "openharmony", "platform": "gitcode"}],
            "raw": {},
            "mode": "live",
        },
        {"source": "cve_findings", "path": "generated:test", "exists": True, "items": [], "raw": {}, "mode": "generated"},
    ]

    calls = {"count": 0}

    def fake_live(params):
        calls["count"] += 1
        return records

    monkeypatch.setattr(huawei_sources, "load_huawei_live", fake_live)
    settings = load_settings()
    settings = settings.model_copy(update={"output_dir": tmp_path})
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    repo.create_pipeline_run(conn, run_id="source_run", domain="threats", pipeline_name="test.sources")
    source_context = PipelineContext(run_id="source_run", pipeline_name="test.sources", domain="threats", settings=settings, conn=conn, artifact_store=ArtifactStore(tmp_path), params={})

    from ai4sec_platform.pipelines.steps.threat_sources import CollectHuaweiSourcesStep

    CollectHuaweiSourcesStep().run(source_context)
    assert calls["count"] == 1

    def fail_live(params):
        raise AssertionError("live loader should not be called when resuming from source run")

    monkeypatch.setattr(huawei_sources, "load_huawei_live", fail_live)
    resumed = huawei_sources.load_huawei_sources(settings, {"resume_from_run_id": "source_run"})
    assert resumed[0]["source"] == "repos"
    assert resumed[0]["items"][0]["name"] == "kernel_parser"


def test_huawei_source_cache_refreshes_selected_sources(monkeypatch, tmp_path) -> None:
    settings = load_settings().model_copy(update={"output_dir": tmp_path})
    calls = {"repos": 0, "firmware": 0}

    def fake_repo_record(registry, params):
        calls["repos"] += 1
        return {"source": "repos", "path": "fake:repos", "exists": True, "items": [{"name": f"repo-{calls['repos']}", "org": "o", "url": "https://gitcode.com/o/repo"}], "raw": {}, "mode": "live"}

    def fake_firmware(registry, params):
        calls["firmware"] += 1
        return {"source": "firmware", "path": "fake:firmware", "exists": True, "items": [{"name": f"fw-{calls['firmware']}"}], "raw": {}, "mode": "live"}

    monkeypatch.setattr(huawei_sources, "_collect_repo_record", fake_repo_record)
    monkeypatch.setattr(huawei_sources, "_collect_firmware_assets", fake_firmware)

    params = {"use_source_cache": True, "sources": ["repos", "firmware"]}
    first = huawei_sources.load_huawei_sources(settings, params)
    second = huawei_sources.load_huawei_sources(settings, params)
    refreshed = huawei_sources.load_huawei_sources(settings, {**params, "refresh_sources": ["repos"]})

    assert calls == {"repos": 2, "firmware": 1}
    assert [record["items"][0]["name"] for record in first] == ["repo-1", "fw-1"]
    assert [record["items"][0]["name"] for record in second] == ["repo-1", "fw-1"]
    assert [record["items"][0]["name"] for record in refreshed] == ["repo-2", "fw-1"]
