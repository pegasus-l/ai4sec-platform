"""T1.5 优先级: 四条资产路径 + P1/P2 兜底。"""
from __future__ import annotations

import json
import sqlite3

import pytest

from ai4sec_platform.domains.capabilities.writeup_repro import priority


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE domain_items (id INTEGER PRIMARY KEY, domain TEXT, item_type TEXT,
                                   title TEXT, payload_json TEXT);
        CREATE TABLE threat_links (repo_id INTEGER, asset_id INTEGER, confidence TEXT);
        CREATE TABLE vulnerability_case_sources (kind TEXT, identifier TEXT, enabled INTEGER);
        CREATE TABLE vulnerability_projects (slug TEXT, packages_json TEXT, enabled INTEGER);
        CREATE TABLE writeup_repro_candidates (
            material_id INTEGER PRIMARY KEY, screenable INTEGER, has_poc INTEGER,
            target_repo TEXT, target_version TEXT, target_cve TEXT, target_product TEXT,
            asset_hit INTEGER DEFAULT 0, asset_ids TEXT DEFAULT '', asset_confidence TEXT DEFAULT '',
            priority TEXT DEFAULT '', priority_reason TEXT DEFAULT ''
        );
    """)
    return conn


def _repo(conn, item_id: int, org: str, name: str, cves: list[str]) -> None:
    conn.execute(
        "INSERT INTO domain_items VALUES (?,?,?,?,?)",
        (item_id, "threats", "target", f"{org}/{name}", json.dumps(
            {"org": org, "name": name, "cve_count": len(cves),
             "cves": [{"cve_id": c} for c in cves]})),
    )


def _asset(conn, item_id: int, title: str) -> None:
    conn.execute("INSERT INTO domain_items VALUES (?,?,?,?,?)",
                 (item_id, "threats", "asset", title, "{}"))


@pytest.fixture(autouse=True)
def _fresh_index():  # type: ignore[no-untyped-def]
    priority._CACHE.update({"at": 0, "cve": {}, "links": {}, "assets": {}, "sources": [], "projects": []})
    yield


def test_a1_a_direct_asset_link_is_p0() -> None:
    conn = _conn()
    _repo(conn, 10, "openeuler", "kernel", ["CVE-2021-44228"])
    _asset(conn, 900, "Atlas 350")
    conn.execute("INSERT INTO threat_links VALUES (10, 900, 'direct')")
    out = priority.compute(conn, {"screenable": 1, "target_cve": "cve-2021-44228"})
    assert out["priority"] == "P0"
    assert out["asset_confidence"] == "direct"
    assert "Atlas 350" in out["asset_ids"]


def test_a2_ecosystem_hit_is_p0_but_says_it_is_not_our_product() -> None:
    conn = _conn()
    _repo(conn, 11, "openharmony", "kernel_linux_6.6", ["CVE-2022-0001"])
    out = priority.compute(conn, {"screenable": 1, "target_cve": "CVE-2022-0001"})
    assert out["priority"] == "P0"
    assert out["asset_confidence"] == "ecosystem"
    assert "不代表我司产品受影响" in out["priority_reason"]


def test_p1_requires_poc_repo_and_version() -> None:
    conn = _conn()
    out = priority.compute(conn, {"screenable": 1, "has_poc": 1,
                                  "target_repo": "github:a/b", "target_version": "1.2.3",
                                  "target_cve": "CVE-2024-9999"})
    assert out["priority"] == "P1"
    assert out["asset_hit"] == 0


def test_a_missing_version_drops_to_p2() -> None:
    conn = _conn()
    out = priority.compute(conn, {"screenable": 1, "has_poc": 1, "target_repo": "github:a/b"})
    assert out["priority"] == "P2"


def test_a_declared_watch_source_is_p0() -> None:
    conn = _conn()
    conn.execute("INSERT INTO vulnerability_case_sources VALUES ('tracked_package', 'PyPI:requests', 1)")
    out = priority.compute(conn, {"screenable": 1, "target_product": "requests"})
    assert out["priority"] == "P0"
    assert out["asset_confidence"] == "declared"


def test_a_project_package_hit_is_p0() -> None:
    conn = _conn()
    conn.execute("INSERT INTO vulnerability_projects VALUES ('github:apache/log4j2', ?, 1)",
                 (json.dumps([{"ecosystem": "Maven", "name": "log4j-core"}]),))
    out = priority.compute(conn, {"screenable": 1, "target_product": "log4j-core"})
    assert out["priority"] == "P0"


def test_an_unreproducible_candidate_gets_no_priority() -> None:
    conn = _conn()
    out = priority.compute(conn, {"screenable": 0})
    assert out["priority"] == ""
    assert "不参与排序" in out["priority_reason"]


def test_assign_writes_only_the_priority_columns() -> None:
    conn = _conn()
    _repo(conn, 12, "o", "r", ["CVE-2020-1"])
    conn.execute(
        "INSERT INTO writeup_repro_candidates (material_id, screenable, has_poc,"
        " target_repo, target_version, target_cve) VALUES (1, 1, 1, '', '', 'CVE-2020-1')")
    conn.execute(
        "INSERT INTO writeup_repro_candidates (material_id, screenable, has_poc,"
        " target_repo, target_version) VALUES (2, 1, 1, 'github:a/b', '1.0')")
    conn.commit()
    counts = priority.assign(conn)
    assert counts["P0"] == 1 and counts["P1"] == 1
    rows = {r["material_id"]: r for r in conn.execute("SELECT * FROM writeup_repro_candidates")}
    assert rows[1]["priority"] == "P0" and rows[2]["priority"] == "P1"
    assert rows[1]["screenable"] == 1 and rows[2]["has_poc"] == 1   # 其它列没被动
