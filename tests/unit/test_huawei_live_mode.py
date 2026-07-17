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


def test_live_connectors_are_disabled_by_default() -> None:
    connector = SourceRegistry().get("gitcode")
    result = connector.fetch(SourceFetchRequest(source_name="gitcode:test", params={"resource": "repos", "org": "openharmony"}))
    assert result.items == []
    assert result.errors == ["live_source_fetch_disabled"]


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
            {"source": "repo_cves", "path": "live:repo_cves", "exists": True, "items": [], "raw": {"orgs": {}}, "mode": "live"},
        ]

    monkeypatch.setattr(huawei_sources, "load_huawei_live", fake_live)
    settings = load_settings()
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    repo.create_pipeline_run(conn, run_id="live_test", domain="threats", pipeline_name="test.live")
    context = PipelineContext(run_id="live_test", pipeline_name="test.live", domain="threats", settings=settings, conn=conn, artifact_store=ArtifactStore(tmp_path), params={"mode": "live", "limit": 10})

    import_result = ImportHuaweiRawStep().run(context)
    NormalizeHuaweiRawStep().run(context)
    build_result = BuildHuaweiThreatItemsStep().run(context)

    assert import_result.metrics["mode"] == "live"
    assert build_result.metrics["items"] >= 1
    item = conn.execute("SELECT * FROM domain_items WHERE domain = 'threats' AND item_type = 'target'").fetchone()
    assert item is not None
