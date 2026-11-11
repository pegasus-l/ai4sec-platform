"""预筛结果的落库口径(2026-11-10)。

三个容易写错、且错了不会报错的地方:

- ``rule_version`` 变了但旧行还留在表里 → 两套口径混着算通过率;
- 重筛一次就把优先级列清零 → 页面上"算过又没算过";
- 模型报错的行落成 ``no_poc`` → 把模型故障记成文章没料。
"""
from __future__ import annotations

import json
import sqlite3

from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities.writeup_repro import store


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def _material(conn: sqlite3.Connection, item_id: int, *, text: str = "body", status: str = "active", kind: str = "material") -> None:
    conn.execute(
        "INSERT INTO domain_items (id, domain, item_type, title, status, source, source_url, primary_date, payload_json, created_at, updated_at) "
        "VALUES (?, 'vulnerabilities', ?, ?, ?, 'src', 'http://x', '2026-11-01', ?, 'now', 'now')",
        (item_id, kind, f"t{item_id}", status, json.dumps({"cleaned_text": text})),
    )


def _row(material_id: int, **kw) -> dict:
    base = {
        "material_id": material_id, "screenable": 1, "reject_reason": "", "has_poc": 1,
        "poc_lang": "c", "poc_verified": 1, "target_kind": "oss_repo",
        "target_repo": "github:acme/foo", "target_version": "2.3.1",
        "target_cve": "", "target_product": "", "target_source": "model", "env_hint": "",
        "claimed_effect": "", "evidence_quote": "", "rule_json": "{}", "screen_json": "{}",
        "rule_version": "rules-v1", "model_profile": "capability_writeup_screener",
        "screened_by": "llm", "screened_at": "2026-11-10T12:00:00Z",
    }
    base.update(kw)
    return base


def test_pending_excludes_already_screened_with_same_rule_version() -> None:
    conn = _conn()
    _material(conn, 1)
    _material(conn, 2)
    store.upsert_candidate(conn, _row(1))
    pending = store.pending_materials(conn, rule_version="rules-v1")
    assert [m["id"] for m in pending] == [2]


def test_new_rule_version_makes_old_rows_pending_again() -> None:
    """规则层改了, 旧结论自动失效 —— 否则两套口径的行混在同一张表里比通过率。"""
    conn = _conn()
    _material(conn, 1)
    store.upsert_candidate(conn, _row(1, rule_version="rules-v1"))
    assert [m["id"] for m in store.pending_materials(conn, rule_version="rules-v2")] == [1]


def test_pending_skips_dropped_and_non_material_rows() -> None:
    conn = _conn()
    _material(conn, 1, status="已淘汰")
    _material(conn, 2, kind="event")
    _material(conn, 3)
    assert [m["id"] for m in store.pending_materials(conn)] == [3]


def test_pending_reads_cleaned_text_out_of_payload() -> None:
    conn = _conn()
    _material(conn, 1, text="hello writeup")
    assert store.pending_materials(conn)[0]["cleaned_text"] == "hello writeup"


def test_pending_falls_back_to_markdown() -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO domain_items (id, domain, item_type, title, payload_json, created_at, updated_at) "
        "VALUES (1, 'vulnerabilities', 'material', 't', ?, 'now', 'now')",
        (json.dumps({"markdown": "# md"}),),
    )
    assert store.pending_materials(conn)[0]["cleaned_text"] == "# md"


def test_upsert_is_idempotent_and_overwrites_verdict() -> None:
    conn = _conn()
    _material(conn, 1)
    store.upsert_candidate(conn, _row(1))
    store.upsert_candidate(conn, _row(1, screenable=0, reject_reason="no_poc"))
    rows = conn.execute("SELECT screenable, reject_reason FROM writeup_repro_candidates").fetchall()
    assert rows == [(0, "no_poc")]


def test_rescreen_does_not_wipe_priority_columns() -> None:
    """优先级是 T1.5 的结论, 一次规则层升级不该把它抹掉。"""
    conn = _conn()
    _material(conn, 1)
    store.upsert_candidate(conn, _row(1))
    conn.execute(
        "UPDATE writeup_repro_candidates SET priority='P0', asset_hit=1, priority_reason='命中资产' WHERE material_id=1"
    )
    store.upsert_candidate(conn, _row(1, rule_version="rules-v2"))
    row = store.get_candidate(conn, 1)
    assert row["priority"] == "P0" and row["asset_hit"] == 1 and row["priority_reason"] == "命中资产"
    assert row["rule_version"] == "rules-v2"


def test_get_candidate_parses_json_columns() -> None:
    conn = _conn()
    _material(conn, 1)
    store.upsert_candidate(conn, _row(1, screen_json='{"confidence": 0.9}', rule_json='{"has_poc": true}'))
    row = store.get_candidate(conn, 1)
    assert row["screen_json"] == {"confidence": 0.9}
    assert row["rule_json"] == {"has_poc": True}


def test_get_candidate_missing_returns_none() -> None:
    assert store.get_candidate(_conn(), 999) is None


def test_screenable_candidates_exclude_rejected() -> None:
    conn = _conn()
    _material(conn, 1)
    _material(conn, 2)
    store.upsert_candidate(conn, _row(1))
    store.upsert_candidate(conn, _row(2, screenable=0, reject_reason="no_poc"))
    assert [c["material_id"] for c in store.screenable_candidates(conn)] == [1]


def test_stats_reports_funnel_with_pending() -> None:
    conn = _conn()
    for i in (1, 2, 3):
        _material(conn, i)
    store.upsert_candidate(conn, _row(1))
    store.upsert_candidate(conn, _row(2, screenable=0, reject_reason="no_poc"))
    stats = store.stats(conn)
    assert stats == {
        "materials_total": 3, "screened": 2, "screenable": 1,
        "reject_reason": {"no_poc": 1}, "pending": 1,
    }
