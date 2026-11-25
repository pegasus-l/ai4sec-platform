"""T5.3 复利指标:复用命中(强/弱)、有/无复用的耗时差、spec 阶段出局率。"""
from __future__ import annotations

import json
import sqlite3

from ai4sec_platform.domains.capabilities.writeup_repro import metrics


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript("""
        CREATE TABLE writeup_repro_tasks (
            id INTEGER PRIMARY KEY, status TEXT, verdict TEXT, failure_reason TEXT,
            duration_seconds INTEGER, tool_calls INTEGER, evidence_json TEXT
        );
        CREATE TABLE writeup_repro_recipes (
            id INTEGER PRIMARY KEY, recipe_key TEXT, material_id INTEGER, degraded INTEGER,
            fingerprint_json TEXT
        );
        CREATE TABLE writeup_repro_patterns (
            id INTEGER PRIMARY KEY, provenance TEXT, backtest_status TEXT
        );
    """)
    return conn


def _task(conn, tid, *, status="success", verdict="success", reason="", dur=100, calls=10,
          reuse=None) -> None:
    evidence = json.dumps({"recipe_reuse": reuse} if reuse else {}, ensure_ascii=False)
    conn.execute(
        "INSERT INTO writeup_repro_tasks VALUES (?,?,?,?,?,?,?)",
        (tid, status, verdict, reason, dur, calls, evidence),
    )


def test_buckets_separate_strong_weak_and_none() -> None:
    conn = _conn()
    _task(conn, 1, dur=100, calls=10)
    _task(conn, 2, dur=200, calls=20, reuse={"used": True, "strength": "weak", "recipe_key": "wr-a"})
    _task(conn, 3, dur=300, calls=30, reuse={"used": True, "strength": "strong", "recipe_key": "wr-a"})
    out = metrics.summary(conn)
    buckets = out["reuse"]["by_bucket"]
    assert buckets["none"]["tasks"] == 1
    assert buckets["weak"]["avg_duration_seconds"] == 200.0
    assert buckets["strong"]["avg_tool_calls"] == 30.0
    assert out["reuse"]["hits"] == {"total": 2, "strong": 1, "weak": 1}
    assert out["reuse"]["top_recipes"] == [{"recipe_key": "wr-a", "times": 2}]


def test_a_missing_strength_counts_as_weak() -> None:
    """老证据(2026-11-25 之前)没有 strength 字段 —— 按弱命中计, 不能算成强。"""
    conn = _conn()
    _task(conn, 1, reuse={"used": True, "recipe_key": "wr-old"})
    out = metrics.summary(conn)
    assert out["reuse"]["hits"] == {"total": 1, "strong": 0, "weak": 1}


def test_spec_stage_rate_counts_only_article_incomplete() -> None:
    conn = _conn()
    _task(conn, 1, status="cannot_repro", verdict="cannot_repro", reason="article_incomplete")
    _task(conn, 2, status="cannot_repro", verdict="cannot_repro", reason="version_mismatch")
    _task(conn, 3)
    out = metrics.summary(conn)
    assert out["tasks"]["spec_stage_dropped"] == 1
    assert out["tasks"]["executed"] == 3
    assert out["tasks"]["spec_stage_rate"] == round(1 / 3, 3)


def test_pattern_traceability_and_backtest_counts() -> None:
    conn = _conn()
    conn.executemany("INSERT INTO writeup_repro_patterns VALUES (?,?,?)", [
        (1, "from_repro", "pass"), (2, "llm_extracted", "fail"), (3, "", ""),
    ])
    out = metrics.summary(conn)
    assert out["patterns"]["total"] == 3
    assert out["patterns"]["traceable"] == 1
    assert out["patterns"]["backtest"] == {"pass": 1, "fail": 1, "pending": 1}


def test_recipe_counts_come_from_the_recipe_table() -> None:
    conn = _conn()
    conn.executemany("INSERT INTO writeup_repro_recipes VALUES (?,?,?,?,?)", [
        (1, "wr-a", 10, 0, "[]"), (2, "wr-b", 10, 1, "[]"), (3, "wr-c", 11, 0, "[]"),
    ])
    out = metrics.summary(conn)
    assert out["recipes"] == {"total": 3, "non_degraded": 2, "materials": 2}


def test_only_executed_tasks_enter_the_duration_buckets() -> None:
    """spec 阶段就出局的任务(耗时 0)不能混进"无复用"桶 —— 否则均值被拉到 94 秒。"""
    conn = _conn()
    _task(conn, 1, status="cannot_repro", verdict="cannot_repro", dur=0, calls=0)
    _task(conn, 2, dur=200, calls=20)
    out = metrics.summary(conn)
    assert out["reuse"]["by_bucket"]["none"]["tasks"] == 1
    assert out["reuse"]["by_bucket"]["none"]["avg_duration_seconds"] == 200.0
