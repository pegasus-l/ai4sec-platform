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
