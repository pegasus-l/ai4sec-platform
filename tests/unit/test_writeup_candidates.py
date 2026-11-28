"""候选列表: 排序、筛选、统计。"""
from __future__ import annotations

import json
import sqlite3

import pytest

from ai4sec_platform.domains.capabilities.writeup_repro import candidates


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE domain_items (id INTEGER PRIMARY KEY, title TEXT, source_url TEXT, payload_json TEXT);
        CREATE TABLE writeup_repro_candidates (
            material_id INTEGER PRIMARY KEY, screenable INTEGER, reject_reason TEXT,
            priority TEXT DEFAULT '', priority_reason TEXT DEFAULT '',
            asset_hit INTEGER DEFAULT 0, asset_ids TEXT DEFAULT '', asset_confidence TEXT DEFAULT '',
            has_poc INTEGER DEFAULT 0, poc_lang TEXT DEFAULT '', target_kind TEXT DEFAULT '',
            target_repo TEXT DEFAULT '', target_version TEXT DEFAULT '', target_cve TEXT DEFAULT '',
            target_product TEXT DEFAULT '', claimed_effect TEXT DEFAULT ''
        );
        CREATE TABLE writeup_repro_tasks (
            id INTEGER PRIMARY KEY, material_id INTEGER, status TEXT, verdict TEXT
        );
    """)
    return conn


def _cand(conn, material_id: int, *, priority="P2", screenable=1, repo="", cve="", reason="") -> None:
    conn.execute(
        "INSERT INTO domain_items VALUES (?,?,?,?)",
        (material_id, f"标题 {material_id}", f"https://example.com/{material_id}",
         json.dumps({"cleaned_text": "x" * 1000})),
    )
    conn.execute(
        "INSERT INTO writeup_repro_candidates (material_id, screenable, priority, priority_reason,"
        " target_repo, target_cve, asset_hit) VALUES (?,?,?,?,?,?,?)",
        (material_id, screenable, priority, reason, repo, cve, 1 if priority == "P0" else 0),
    )


def test_ordering_puts_p0_first_and_unranked_last() -> None:
    conn = _conn()
    _cand(conn, 1, priority="")
    _cand(conn, 2, priority="P2")
    _cand(conn, 3, priority="P0")
    _cand(conn, 4, priority="P1")
    conn.commit()
    items, total = candidates.list_candidates(conn, screenable=None)
    assert total == 4
    assert [item["priority"] for item in items] == ["P0", "P1", "P2", ""]


def test_only_screenable_by_default_and_filters_work() -> None:
    conn = _conn()
    _cand(conn, 1, priority="P0", cve="CVE-2020-1")
    _cand(conn, 2, priority="P1", repo="github:a/b")
    _cand(conn, 3, priority="P2", screenable=0)
    conn.commit()
    items, total = candidates.list_candidates(conn)
    assert total == 2 and all(item["screenable"] == 1 for item in items)
    hit, n = candidates.list_candidates(conn, q="CVE-2020-1")
    assert n == 1 and hit[0]["material_id"] == 1
    none, n0 = candidates.list_candidates(conn, priority="P2")
    assert n0 == 0 and none == []


def test_an_unknown_priority_is_an_error() -> None:
    conn = _conn()
    with pytest.raises(ValueError):
        candidates.list_candidates(conn, priority="P9")


def test_task_state_is_joined_for_each_candidate() -> None:
    conn = _conn()
    _cand(conn, 1, priority="P0")
    _cand(conn, 2, priority="P1")
    conn.execute("INSERT INTO writeup_repro_tasks VALUES (7, 1, 'success', 'success')")
    conn.commit()
    items, _ = candidates.list_candidates(conn)
    by_id = {item["material_id"]: item for item in items}
    assert by_id[1]["task_id"] == 7 and by_id[1]["task_verdict"] == "success"
    assert by_id[2]["task_id"] is None
    only, n = candidates.list_candidates(conn, has_task=True)
    assert n == 1 and only[0]["material_id"] == 1


def test_stats_count_priorities_and_tasked_materials() -> None:
    conn = _conn()
    _cand(conn, 1, priority="P0")
    _cand(conn, 2, priority="P2")
    _cand(conn, 3, priority="P2")
    _cand(conn, 4, priority="P2", screenable=0)
    conn.execute("INSERT INTO writeup_repro_tasks VALUES (9, 2, 'success', 'success')")
    conn.commit()
    out = candidates.stats(conn)
    assert out["screenable"] == 3
    assert out["by_priority"] == {"P0": 1, "P1": 0, "P2": 2}
    assert out["with_task"] == 1


def test_the_payload_is_not_selected() -> None:
    """列表只取标题/URL —— 素材 payload 有几十 KB, SELECT * 会让分页变成拉全库。"""
    conn = _conn()
    _cand(conn, 1)
    conn.commit()
    items, _ = candidates.list_candidates(conn)
    assert items[0]["title"] == "标题 1"
    assert "payload_json" not in items[0]
