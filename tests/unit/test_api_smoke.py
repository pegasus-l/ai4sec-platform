from __future__ import annotations

from fastapi.testclient import TestClient

from ai4sec_platform.app.main import app


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
    assert any(item["name"] == "legacy.sample_import" for item in pipelines.json()["items"])

    response = client.post("/api/runs", json={"pipeline_name": "legacy.sample_import", "reset": True})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["pipeline_name"] == "legacy.sample_import"

    detail = client.get(f"/api/runs/{data['run_id']}")
    assert detail.status_code == 200
    detail_data = detail.json()
    assert detail_data["tasks"]
    assert any(item["artifact_type"] == "manifest" for item in detail_data["artifacts"])


def test_raw_pipeline_builds_from_source_raw_files() -> None:
    client = TestClient(app)
    response = client.post(
        "/api/runs",
        json={"pipeline_name": "news.ai_for_sec_raw_pipeline", "reset": True, "params": {"date": "2026-07-10"}},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["pipeline_name"] == "news.ai_for_sec_raw_pipeline"
    step_names = [step["name"] for step in data["summary"]["steps"]]
    assert step_names == ["import_ai_for_sec_raw", "normalize_ai_for_sec_raw", "build_raw_news_domain_items"]

    detail = client.get(f"/api/runs/{data['run_id']}").json()
    artifact_types = {item["artifact_type"] for item in detail["artifacts"]}
    assert "raw_arxiv" in artifact_types
    assert "normalized_news_items" in artifact_types
    assert "manifest" in artifact_types

    news = client.get("/api/news/today").json()
    assert news["items"]
    first = news["items"][0]
    assert "raw_pipeline" in first["tags"]


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


def test_threat_and_vulnerability_raw_pipelines_run() -> None:
    client = TestClient(app)
    cases = [
        ("threats.huawei_raw_pipeline", {"limit": 20}, "/api/threats/today"),
        ("vulnerabilities.material_raw_pipeline", {"report_limit": 2, "item_limit": 20}, "/api/vulnerabilities/today"),
    ]
    for pipeline_name, params, check_path in cases:
        response = client.post("/api/runs", json={"pipeline_name": pipeline_name, "reset": True, "params": params})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["pipeline_name"] == pipeline_name
        assert len(data["summary"]["steps"]) == 3
        detail = client.get(f"/api/runs/{data['run_id']}").json()
        assert any(item["artifact_type"] == "manifest" for item in detail["artifacts"])
        domain_data = client.get(check_path).json()
        assert domain_data["items"]
