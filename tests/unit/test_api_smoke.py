from __future__ import annotations

from fastapi.testclient import TestClient

from ai4sec_platform.app.main import app


def _patch_threat_connector_records(monkeypatch) -> None:
    records = [
        {
            "source": "repos",
            "path": "connector:test/repos",
            "exists": True,
            "mode": "connector",
            "items": [
                {
                    "name": "security",
                    "url": "https://gitcode.com/openharmony/security",
                    "description": "security advisories CVE-2024-12345",
                    "star_count": 20,
                    "org": "openharmony",
                    "platform": "gitcode",
                    "security_files": [{"path": "security.md", "content": "| Component | ID | Severity |\n| kernel_parser | CVE-2024-12345 | Critical |"}],
                },
                {
                    "name": "kernel_parser",
                    "url": "https://gitcode.com/openharmony/kernel_parser",
                    "description": "kernel parser security boundary RCE exploit",
                    "star_count": 99,
                    "org": "openharmony",
                    "platform": "gitcode",
                    "issues": [{"title": "CVE-2024-12345 RCE parser crash", "description": "security vulnerability PoC"}],
                },
            ],
            "raw": {},
        },
        {
            "source": "firmware",
            "path": "connector:test/firmware",
            "exists": True,
            "mode": "connector",
            "items": [{"productModel": "AscendFirmware", "packageCount": 5, "latestRelease": "2026-07-01"}],
            "raw": {},
        },
    ]

    def fake_load(settings, params):
        return records

    from ai4sec_platform.domains.threats.adapters import huawei_sources
    from ai4sec_platform.pipelines.steps import threat_asset_import, threat_cve_scout, threat_raw, threat_score_filter, threat_sources

    monkeypatch.setattr(huawei_sources, "load_huawei_sources", fake_load)
    monkeypatch.setattr(huawei_sources, "load_huawei_live", lambda params: records)
    monkeypatch.setattr(threat_raw, "load_huawei_sources", fake_load)
    monkeypatch.setattr(threat_cve_scout, "load_huawei_sources", fake_load)
    monkeypatch.setattr(threat_score_filter, "load_huawei_sources", fake_load)
    monkeypatch.setattr(threat_asset_import, "load_huawei_sources", fake_load)
    monkeypatch.setattr(threat_sources, "load_huawei_sources", fake_load)


def test_health_endpoint() -> None:
    client = TestClient(app)
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_dashboard_overview_shape() -> None:
    client = TestClient(app)
    response = client.get("/api/dashboard/overview")
    assert response.status_code == 200
    data = response.json()
    assert data["production_writes"] is False
    assert {item["domain"] for item in data["domains"]} == {"news", "capabilities", "threats", "vulnerabilities"}


def test_frontend_index() -> None:
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "AI4SEC TMG" in response.text
    assert "顶部任务栏" in response.text


def test_run_pipeline_endpoint_triggers_import() -> None:
    client = TestClient(app)
    pipelines = client.get("/api/runs/pipelines")
    assert pipelines.status_code == 200
    assert any(item["name"] == "news.legacy_raw_pipeline" for item in pipelines.json()["items"])
    assert not any(item["name"] == "legacy.sample_import" for item in pipelines.json()["items"])

    response = client.post("/api/runs", json={"pipeline_name": "news.legacy_raw_pipeline", "reset": True, "wait": True, "params": {"date": "2026-07-10"}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["pipeline_name"] == "news.legacy_raw_pipeline"

    detail = client.get(f"/api/runs/{data['run_id']}")
    assert detail.status_code == 200
    detail_data = detail.json()
    assert detail_data["tasks"]
    assert any(item["artifact_type"] == "manifest" for item in detail_data["artifacts"])


def test_raw_pipeline_builds_from_source_raw_files() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/runs",
        json={"pipeline_name": "news.legacy_raw_pipeline", "reset": True, "wait": True, "params": {"date": "2026-07-10"}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["pipeline_name"] == "news.legacy_raw_pipeline"
    step_names = [step["name"] for step in data["summary"]["steps"]]
    assert step_names == ["collect_news_sources", "extract_news_references", "normalize_news_items", "deduplicate_news_candidates", "resolve_news_candidate_links", "gate_news_candidates_with_tech_map", "enrich_news_candidates_with_model", "build_news_items", "build_news_daily_report", "audit_news_quality"]

    detail = client.get(f"/api/runs/{data['run_id']}").json()
    artifact_types = {item["artifact_type"] for item in detail["artifacts"]}
    assert "raw_news_arxiv" in artifact_types
    assert "normalized_news_items" in artifact_types
    assert "manifest" in artifact_types

    news = client.get("/api/news/today").json()
    assert news["highlights"]
    assert news["kpis"]["new_count"] > 0


def test_v9_contract_endpoint_aliases_exist() -> None:
    client = TestClient(app)
    paths = [
        "/api/news/page",
        "/api/news/sources",
        "/api/news/items",
        "/api/capabilities/items",
        "/api/capabilities/repro-runs",
        "/api/capabilities/conversions",
        "/api/threats/targets",
        "/api/threats/tracking",
        "/api/threats/graph",
        "/api/threats/risk-assessments",
        "/api/threats/assets",
        "/api/threats/cve-scout",
        "/api/threats/attack-surface",
        "/api/threats/reports",
        "/api/vulnerabilities/materials",
        "/api/vulnerabilities/knowledge",
        "/api/vulnerabilities/migration-queue",
        "/api/operations/tasks",
        "/api/operations/sources",
        "/api/operations/rules",
        "/api/operations/quality-findings",
        "/api/operations/queue-items",
    ]
    for path in paths:
        response = client.get(path)
        assert response.status_code == 200, path


def test_threat_and_vulnerability_raw_pipelines_run(monkeypatch) -> None:
    _patch_threat_connector_records(monkeypatch)
    client = TestClient(app)
    cases = [
        ("threats.huawei_raw_pipeline", {"limit": 20}, "/api/threats/today"),
        ("vulnerabilities.material_local_raw_import", {"report_limit": 2, "item_limit": 20}, "/api/vulnerabilities/today"),
    ]
    for pipeline_name, params, check_path in cases:
        response = client.post("/api/runs", json={"pipeline_name": pipeline_name, "reset": True, "wait": True, "params": params})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["pipeline_name"] == pipeline_name
        assert len(data["summary"]["steps"]) == 3
        detail = client.get(f"/api/runs/{data['run_id']}").json()
        assert any(item["artifact_type"] == "manifest" for item in detail["artifacts"])
        domain_data = client.get(check_path).json()
        assert domain_data["items"]


def test_capability_pipeline_assesses_news_candidates() -> None:
    client = TestClient(app)
    news_run = client.post(
        "/api/runs",
        json={"pipeline_name": "news.legacy_raw_pipeline", "reset": True, "wait": True, "params": {"date": "2026-07-10"}},
    )
    assert news_run.status_code == 200
    response = client.post("/api/runs", json={"pipeline_name": "capabilities.from_news_pipeline", "wait": True, "params": {"limit": 10}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["summary"]["steps"][1]["metrics"]["assessed"] == 10
    detail = client.get(f"/api/runs/{data['run_id']}").json()
    assert any(item["artifact_type"] == "capability_assessments" for item in detail["artifacts"])
    calls = client.get("/api/operations/model-calls").json()
    assert calls["items"]


def test_vulnerability_knowledge_pipeline_extracts_candidates() -> None:
    client = TestClient(app)
    raw_run = client.post(
        "/api/runs",
        json={"pipeline_name": "vulnerabilities.material_local_raw_import", "reset": True, "wait": True, "params": {"report_limit": 2, "item_limit": 20}},
    )
    assert raw_run.status_code == 200
    response = client.post("/api/runs", json={"pipeline_name": "vulnerabilities.knowledge_extraction_pipeline", "wait": True, "params": {"limit": 5}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["summary"]["steps"][1]["metrics"]["extracted"] > 0
    knowledge = client.get("/api/vulnerabilities/knowledge").json()
    assert knowledge["items"]
    assert knowledge["items"][0]["source_material_id"]
    queue = client.get("/api/vulnerabilities/migration-queue").json()
    assert queue["items"]


def test_threat_risk_pipeline_reasons_targets(monkeypatch) -> None:
    _patch_threat_connector_records(monkeypatch)
    client = TestClient(app)
    raw_run = client.post("/api/runs", json={"pipeline_name": "threats.huawei_raw_pipeline", "reset": True, "wait": True, "params": {"limit": 30}})
    assert raw_run.status_code == 200
    response = client.post("/api/runs", json={"pipeline_name": "threats.risk_reasoning_pipeline", "wait": True, "params": {"limit": 8}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["summary"]["steps"][1]["metrics"]["reasoned"] > 0
    assessments = client.get("/api/threats/risk-assessments").json()
    assert assessments["items"]
    calls = client.get("/api/operations/model-calls?domain=threats").json()
    assert calls["items"]


def test_huawei_full_migration_pipeline_runs_and_exposes_reports(monkeypatch) -> None:
    _patch_threat_connector_records(monkeypatch)
    client = TestClient(app)
    response = client.post("/api/runs", json={"pipeline_name": "threats.huawei_full_migration_pipeline", "reset": True, "wait": True, "params": {"limit": 5, "top_n": 5}})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    step_names = [step["name"] for step in data["summary"]["steps"]]
    assert "huawei_cve_scout" in step_names
    assert "huawei_attack_surface_score" in step_names
    assert "build_huawei_threat_report" in step_names
    assert client.get("/api/threats/cve-scout").json()["status"] == "ok"
    assert client.get("/api/threats/cve-compare").status_code == 404
    assert client.get("/api/threats/attack-surface").json()["status"] == "ok"
    assert client.get("/api/threats/attack-surface-compare").status_code == 404
    assert client.get("/api/threats/reports").json()["status"] == "ok"


def test_frontend_v9_contract_returns_all_page_blocks(monkeypatch) -> None:
    _patch_threat_connector_records(monkeypatch)
    client = TestClient(app)
    client.post("/api/runs", json={"pipeline_name": "news.legacy_raw_pipeline", "reset": True, "wait": True, "params": {"date": "2026-07-10"}})
    client.post("/api/runs", json={"pipeline_name": "capabilities.from_news_pipeline", "wait": True, "params": {"limit": 3}})
    client.post("/api/runs", json={"pipeline_name": "threats.huawei_raw_pipeline", "wait": True, "params": {"limit": 10}})
    client.post("/api/runs", json={"pipeline_name": "vulnerabilities.material_local_raw_import", "wait": True, "params": {"report_limit": 1, "item_limit": 10}})
    response = client.get("/api/frontend/v9")
    assert response.status_code == 200
    data = response.json()
    assert data["manifest"]["data_mode"] == "connector_pipeline"
    assert data["news"]["items"]
    assert data["capability"]["today"]
    assert data["threat"]["targets"]
    assert data["vuln"]["materials"]
    assert "tasks" in data["ops"]


def test_frontend_v9_file_contract_aliases_sample_json_paths() -> None:
    client = TestClient(app)
    response = client.get("/api/frontend/v9/files/manifest.json")
    assert response.status_code == 200
    assert response.json()["data_mode"] == "connector_pipeline"
    news_items = client.get("/api/frontend/v9/files/news/items.json")
    assert news_items.status_code == 200
    assert isinstance(news_items.json(), list)
