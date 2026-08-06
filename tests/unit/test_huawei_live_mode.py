from __future__ import annotations

import json

from ai4sec_platform.domains.threats.adapters import huawei_sources
from ai4sec_platform.pipelines.steps.threat_raw import ImportHuaweiRawStep, NormalizeHuaweiRawStep, BuildHuaweiThreatItemsStep, _all_normalized_threat_items
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


def test_all_normalized_threat_items_are_loaded_beyond_legacy_cap() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    repo.create_pipeline_run(conn, run_id="large_threat_run", domain="threats", pipeline_name="test.large")
    conn.executemany(
        """
        INSERT INTO normalized_items (
            run_id, domain, item_key, source, source_type, title, url,
            primary_date, normalized_json, raw_artifact_id, created_at
        ) VALUES ('large_threat_run', 'threats', ?, 'repos', 'repo', ?, '', '', '{}', NULL, '')
        """,
        ((f"repo:{index}", f"repo-{index}") for index in range(10_001)),
    )

    items = _all_normalized_threat_items(conn, "large_threat_run")

    assert len(items) == 10_001
    assert items[-1]["item_key"] == "repo:10000"


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

    def fake_repo_records(registry, params):
        calls["repos"] += 1
        return [{"source": "repos", "path": "fake:repos", "exists": True, "items": [{"name": f"repo-{calls['repos']}", "org": "o", "url": "https://gitcode.com/o/repo"}], "raw": {}, "mode": "live"}]

    def fake_firmware(registry, params):
        calls["firmware"] += 1
        return {"source": "firmware", "path": "fake:firmware", "exists": True, "items": [{"name": f"fw-{calls['firmware']}"}], "raw": {}, "mode": "live"}

    monkeypatch.setattr(huawei_sources, "_collect_repo_records", fake_repo_records)
    monkeypatch.setattr(huawei_sources, "_collect_firmware_assets", fake_firmware)

    params = {"use_source_cache": True, "sources": ["repos", "firmware"]}
    first = huawei_sources.load_huawei_sources(settings, params)
    second = huawei_sources.load_huawei_sources(settings, params)
    refreshed = huawei_sources.load_huawei_sources(settings, {**params, "refresh_sources": ["repos"]})

    assert calls == {"repos": 2, "firmware": 1}
    assert [record["items"][0]["name"] for record in first] == ["repo-1", "fw-1"]
    assert [record["items"][0]["name"] for record in second] == ["repo-1", "fw-1"]
    assert [record["items"][0]["name"] for record in refreshed] == ["repo-2", "fw-1"]


def test_full_scan_repo_collection_delegates_pagination_to_connector() -> None:
    requested_pages = []

    class FakeConnector:
        def fetch(self, request):
            page = request.params["page"]
            requested_pages.append(page)
            items = [{"name": f"repo-{page}-{idx}", "web_url": f"https://gitcode.com/openharmony/repo-{page}-{idx}", "star_count": idx} for idx in range(100)]
            return type("Result", (), {"errors": [], "items": items})()

    class FakeRegistry:
        def get(self, platform):
            return FakeConnector()

    repos = huawei_sources._collect_live_repos(FakeRegistry(), {"scan_profile": "full", "orgs": ["gitcode:openharmony"], "max_workers": 1})

    assert len(repos) == 100
    assert requested_pages == [1]


def test_gitcode_connector_marks_full_last_page_as_truncated(monkeypatch) -> None:
    class FakeResponse:
        def read(self):
            return json.dumps([{"name": "repo", "web_url": "https://gitcode.com/org/repo"}]).encode()

    monkeypatch.setattr("ai4sec_platform.sources.connectors.threats.gitcode.urllib.request.urlopen", lambda request, timeout: FakeResponse())
    monkeypatch.setattr("ai4sec_platform.sources.connectors.threats.gitcode.time.sleep", lambda seconds: None)
    connector = SourceRegistry().get("gitcode")

    result = connector.fetch(
        SourceFetchRequest(
            source_name="gitcode:test",
            params={"resource": "repos", "org": "test", "per_page": 1, "max_pages": 2},
        )
    )

    assert len(result.items) == 2
    assert result.metadata["truncated"] is True
    assert result.errors == ["pagination limit reached at page 2 with a full page of 1 items"]


def test_ascendhub_empty_target_is_reported_as_source_gap() -> None:
    class EmptyConnector:
        def fetch(self, request):
            return type("Result", (), {"errors": [], "items": []})()

    class FakeRegistry:
        def get(self, name):
            assert name == "hiascend"
            return EmptyConnector()

    record = huawei_sources._collect_ascendhub_assets(
        FakeRegistry(),
        {
            "scan_profile": "full",
            "ascendhub_targets": [{"hub_id": "missing", "name": "missing-model"}],
            "ascendhub_tag_pages": 1,
        },
    )

    assert record["exists"] is False
    assert record["raw"]["missing_targets"] == [{"hub_id": "missing", "name": "missing-model", "reason": "detail_and_tags_empty"}]


def test_security_materials_are_org_level_not_project_copies(monkeypatch) -> None:
    fetches = []

    class FakeConnector:
        def fetch(self, request):
            fetches.append(request.params)
            resource = request.params.get("resource")
            if resource == "issues":
                return type("Result", (), {"errors": [], "items": [{"title": "telephony_sms_mms CVE-2026-33333", "description": "高危"}]})()
            if resource == "pull_requests":
                return type("Result", (), {"errors": [], "items": []})()
            if resource == "contents":
                return type("Result", (), {"errors": [], "items": [{"type": "file", "path": "security-disclosure/2026-07.md", "name": "2026-07.md"}]})()
            if resource == "file":
                return type("Result", (), {"errors": [], "items": [], "raw_text": "| Component | ID | Severity |\n| telephony_sms_mms | CVE-2026-44444 | 高危 |"})()
            return type("Result", (), {"errors": [], "items": []})()

    class FakeRegistry:
        def get(self, platform):
            return FakeConnector()

    repos = [
        {"platform": "gitcode", "org": "openharmony", "name": "security", "url": "https://gitcode.com/openharmony/security", "description": "security", "star_count": 10},
        {"platform": "gitcode", "org": "openharmony", "name": "telephony_sms_mms", "url": "https://gitcode.com/openharmony/telephony_sms_mms", "description": "telephony", "star_count": 20},
    ]
    monkeypatch.setattr(huawei_sources, "_collect_live_repos_with_errors", lambda registry, params: (repos, []))
    monkeypatch.setattr(huawei_sources, "_enrich_project_issues", lambda registry, repos, params: repos)

    records = huawei_sources._collect_repo_records(FakeRegistry(), {"security_file_limit": 5})
    repo_record = next(record for record in records if record["source"] == "repos")
    materials_record = next(record for record in records if record["source"] == "org_security_materials")

    assert "org_security_materials" not in repo_record["items"][1]
    assert len(materials_record["items"]) == 2
    assert {item["material_type"] for item in materials_record["items"]} == {"security_repo_issue", "security_repo_file"}
