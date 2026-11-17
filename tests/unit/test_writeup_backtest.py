"""回测:拿 pattern 回到自己的来源上跑。四条边界要锁死。

- 没有位置 / 检索式不合法 / 扫不到文件 → ``unverified``, 不能算失败;
- 扫到候选但目标不在 → ``fail``, 且要降级(不进 verified), 但不能删;
- 回测自己的异常不能改任务结论。
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from ai4sec_platform.domains.capabilities.writeup_repro import backtest


PATTERN = {
    "invariant": "检查与打开必须作用于同一对象",
    "code_feature": "exists() 后 os.open(O_TRUNC) 且无 O_NOFOLLOW",
    "audit_entry": "可预测路径的锁文件",
}


# ---------------------------------------------------------------- 检索式

def test_a_normal_rule_is_accepted() -> None:
    rule = backtest.normalize_rule({"path_glob": "*.py", "include": ["O_TRUNC"], "exclude": ["O_NOFOLLOW"]})
    assert rule == {"path_glob": "*.py", "include": ["O_TRUNC"], "exclude": ["O_NOFOLLOW"]}


def test_a_rule_without_include_is_rejected() -> None:
    assert backtest.normalize_rule({"include": []}) is None
    assert backtest.normalize_rule({"exclude": ["x"]}) is None


def test_an_invalid_regex_is_rejected() -> None:
    assert backtest.normalize_rule({"include": ["O_TRUNC("]}) is None


def test_too_many_regexes_are_rejected() -> None:
    assert backtest.normalize_rule({"include": ["a", "b", "c", "d", "e"]}) is None


def test_a_long_regex_is_rejected() -> None:
    assert backtest.normalize_rule({"include": ["a" * 400]}) is None


# ---------------------------------------------------------------- 目标定位

def test_the_target_path_produces_short_suffixes() -> None:
    assert backtest.target_suffixes("src/filelock/_unix.py") == [
        "src/filelock/_unix.py", "filelock/_unix.py", "_unix.py",
    ]


def test_an_empty_location_has_no_suffix() -> None:
    assert backtest.target_suffixes("") == []
    assert backtest.target_suffixes("  ") == []


# ---------------------------------------------------------------- 三种结论

def _stub(monkeypatch: pytest.MonkeyPatch, *, rule_ok: bool = True, scan_result: dict | None = None) -> None:
    monkeypatch.setattr(backtest, "build_rule", lambda pattern, target: (
        {"status": "ok", "rule": {"path_glob": "*.py", "include": ["O_TRUNC"], "exclude": []}}
        if rule_ok else {"status": "error", "rule": {}, "reason": "坏正则"}
    ))
    monkeypatch.setattr(backtest, "scan", lambda *a, **kw: scan_result or {"status": "error", "reason": "没连上"})


def test_a_hit_is_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, scan_result={"status": "ok", "files_scanned": 13, "candidates_count": 3,
                                    "target_hit": True, "target_rank": 1, "sample": ["a"]})
    result = backtest.backtest_pattern(PATTERN, "src/filelock/_unix.py", 8)
    assert result["status"] == "pass"
    assert result["target_rank"] == 1
    assert result["candidates"] == 3


def test_candidates_without_the_target_is_a_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, scan_result={"status": "ok", "files_scanned": 13, "candidates_count": 3,
                                    "target_hit": False, "target_rank": 0})
    result = backtest.backtest_pattern(PATTERN, "src/filelock/_unix.py", 8)
    assert result["status"] == "fail"


def test_scanning_nothing_is_unverified_not_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """规则太窄、一个候选都没有 —— 说明不了对错, 不能记成 fail。"""
    _stub(monkeypatch, scan_result={"status": "ok", "files_scanned": 400, "candidates_count": 0,
                                    "target_hit": False})
    result = backtest.backtest_pattern(PATTERN, "src/filelock/_unix.py", 8)
    assert result["status"] == "unverified"


def test_no_location_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch)
    result = backtest.backtest_pattern(PATTERN, "", 8)
    assert result["status"] == "unverified"


def test_a_broken_rule_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, rule_ok=False)
    result = backtest.backtest_pattern(PATTERN, "src/x.py", 8)
    assert result["status"] == "unverified"


def test_no_workspace_is_unverified(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub(monkeypatch, scan_result={"status": "no_workspace", "reason": "工作目录不存在"})
    result = backtest.backtest_pattern(PATTERN, "src/x.py", 8)
    assert result["status"] == "unverified"


# ---------------------------------------------------------------- 落库

def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE writeup_repro_patterns (id INTEGER PRIMARY KEY, report_id INTEGER,"
        " invariant TEXT, provenance TEXT NOT NULL DEFAULT 'from_repro',"
        " backtest_status TEXT NOT NULL DEFAULT '', backtest_json TEXT NOT NULL DEFAULT '',"
        " backtested_at TEXT NOT NULL DEFAULT '')"
    )
    conn.execute("INSERT INTO writeup_repro_patterns (id, report_id, invariant) VALUES (1, 8, 'x')")
    conn.commit()
    return conn


def test_a_pass_is_recorded_with_its_rule() -> None:
    conn = _conn()
    backtest.store(conn, 1, {"status": "pass", "candidates": 3, "rule": {"include": ["x"]}})
    row = conn.execute("SELECT * FROM writeup_repro_patterns WHERE id = 1").fetchone()
    assert row["backtest_status"] == "pass"
    assert json.loads(row["backtest_json"])["candidates"] == 3
    assert row["backtested_at"]
    assert row["provenance"] == "from_repro"


def test_a_fail_demotes_but_keeps_the_row() -> None:
    conn = _conn()
    backtest.store(conn, 1, {"status": "fail", "candidates": 3})
    row = conn.execute("SELECT * FROM writeup_repro_patterns WHERE id = 1").fetchone()
    assert row["backtest_status"] == "fail"
    assert row["provenance"] == "llm_extracted"
    assert conn.execute("SELECT COUNT(*) FROM writeup_repro_patterns").fetchone()[0] == 1
