import sqlite3

from fastapi.testclient import TestClient

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.app.main import create_app
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.repositories import create_domain_item, replace_threat_asset_associations


def test_target_assets_returns_normalized_associations_in_confidence_order() -> None:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    target_id = create_domain_item(conn, domain="threats", item_type="target", title="cann/ge", score=90)
    direct_id = create_domain_item(
        conn,
        domain="threats",
        item_type="asset",
        title="Ascend firmware",
        score=40,
        source="firmware",
        payload={"source": "firmware", "raw": {"modelName": "Atlas"}},
    )
    inferred_id = create_domain_item(
        conn,
        domain="threats",
        item_type="asset",
        title="Ascend image",
        score=80,
        source="ascendhub",
        payload={"source": "ascendhub", "raw": {"name": "CANN image"}},
    )
    replace_threat_asset_associations(
        conn,
        asset_item_id=inferred_id,
        associations=[{"repo_id": str(target_id), "confidence": "inferred", "reason": "name match"}],
    )
    replace_threat_asset_associations(
        conn,
        asset_item_id=direct_id,
        associations=[{"repo_id": target_id, "confidence": "direct", "reason": "manifest reference"}],
    )
    app = create_app()
    app.dependency_overrides[get_db] = lambda: conn
    try:
        response = TestClient(app).get(f"/api/threats/targets/{target_id}/assets")
        missing = TestClient(app).get("/api/threats/targets/999999/assets")
    finally:
        app.dependency_overrides.pop(get_db, None)
        conn.close()

    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 2
    assert [item["id"] for item in body["items"]] == [direct_id, inferred_id]
    assert body["items"][0]["association"] == {"confidence": "direct", "reason": "manifest reference"}
    assert missing.status_code == 404


def test_target_assets_query_uses_target_association_index() -> None:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    plan = conn.execute(
        """
        EXPLAIN QUERY PLAN
        SELECT di.id
        FROM threat_asset_associations AS taa INDEXED BY idx_threat_asset_assoc_target
        JOIN domain_items di ON di.id = taa.asset_item_id
        WHERE taa.target_item_id = 1 AND di.domain = 'threats' AND di.item_type = 'asset'
        ORDER BY taa.confidence, di.score DESC, di.id DESC LIMIT 50
        """
    ).fetchall()
    details = " ".join(str(row["detail"]) for row in plan)
    conn.close()

    assert "idx_threat_asset_assoc_target" in details
    assert "payload_json" not in details
