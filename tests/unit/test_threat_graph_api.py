import sqlite3

from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import create_app
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.repositories import create_domain_item, upsert_threat_item_dimensions


def _client() -> tuple[TestClient, sqlite3.Connection]:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    item_id = create_domain_item(
        conn,
        domain="threats",
        item_type="target",
        title="cann/ge",
        score=93,
        payload={"large_marker": "must-not-appear-in-summary", "cves": [{"cve_id": "CVE-2026-42033"}]},
    )
    upsert_threat_item_dimensions(
        conn,
        domain_item_id=item_id,
        attack_surface="parser/codec",
        attack_surface_grade="A",
        cve_count=8,
        total_sec_count=12,
        org="cann",
        cve_sample=[
            {"cve_id": f"CVE-2026-{42033 + index}", "severity": "high"}
            for index in range(5)
        ],
    )
    app = create_app()
    app.dependency_overrides[get_db] = lambda: conn
    return TestClient(app), conn


def test_graph_defaults_to_lightweight_target_summary() -> None:
    client, conn = _client()
    response = client.get("/api/threats/graph")
    conn.close()

    assert response.status_code == 200
    body = response.json()
    item = body["targets"]["items"][0]
    assert body["targets"]["limit"] == 50
    assert body["filters"]["fields"] == "summary"
    assert item["raw_org"] == "cann"
    assert item["attack_surface_summary"]["surface"] == "parser/codec"
    assert item["signals_summary"]["cve_count"] == 8
    assert len(item["payload"]["cves"]) == 5
    assert "large_marker" not in response.text


def test_graph_full_fields_preserve_complete_payload() -> None:
    client, conn = _client()
    response = client.get("/api/threats/graph", params={"fields": "full"})
    invalid = client.get("/api/threats/graph", params={"fields": "invalid"})
    conn.close()

    assert response.status_code == 200
    assert response.json()["targets"]["items"][0]["payload"]["large_marker"] == "must-not-appear-in-summary"
    assert invalid.status_code == 422


def test_graph_order_query_uses_covering_sort_index() -> None:
    _, conn = _client()
    plan = conn.execute(
        """
        EXPLAIN QUERY PLAN
        SELECT id, title, score FROM domain_items
        WHERE domain = 'threats' AND item_type = 'target'
        ORDER BY score DESC, id DESC LIMIT 50 OFFSET 0
        """
    ).fetchall()
    details = " ".join(str(row["detail"]) for row in plan)
    conn.close()

    assert "idx_domain_items_graph_order" in details
    assert "TEMP B-TREE" not in details
