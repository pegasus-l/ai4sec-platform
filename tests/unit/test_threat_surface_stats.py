import sqlite3

from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import create_app
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.repositories import create_domain_item, upsert_threat_item_dimensions


def test_surface_stats_aggregates_dimension_table_without_payload_scan() -> None:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    kernel_id = create_domain_item(conn, domain="threats", item_type="target", title="org/kernel", payload={"ignored": True})
    unknown_id = create_domain_item(conn, domain="threats", item_type="target", title="org/unknown", payload={"ignored": True})
    upsert_threat_item_dimensions(conn, domain_item_id=kernel_id, attack_surface="kernel", cve_count=4, total_sec_count=7)
    upsert_threat_item_dimensions(conn, domain_item_id=unknown_id, attack_surface="", cve_count=1, total_sec_count=2)
    app = create_app()
    app.dependency_overrides[get_db] = lambda: conn
    try:
        response = TestClient(app).get("/api/threats/surface-stats")
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert response.status_code == 200
    assert response.json() == {
        "total_repos": 2,
        "total_cves": 5,
        "total_sec": 9,
        "per_surface": {
            "kernel": {"count": 1, "cves": 4, "sec": 7},
            "unknown": {"count": 1, "cves": 1, "sec": 2},
        },
    }


def test_surface_stats_query_plan_does_not_scan_domain_items() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)

    plan = conn.execute(
        """
        EXPLAIN QUERY PLAN
        SELECT COALESCE(NULLIF(attack_surface, ''), 'unknown') AS surface,
               COUNT(*), COALESCE(SUM(cve_count), 0), COALESCE(SUM(total_sec_count), 0)
        FROM threat_item_dimensions
        GROUP BY surface
        """
    ).fetchall()
    details = " ".join(str(row["detail"]) for row in plan)

    assert "domain_items" not in details
    assert "payload_json" not in details
    assert "idx_threat_dimensions_surface_aggregate" in details
    assert "TEMP B-TREE" not in details
