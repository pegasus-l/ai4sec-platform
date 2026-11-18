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


# ---------------------------------------------------------------- 找洞口径

class _Spy:
    def __init__(self, result: dict) -> None:
        self.result = result
        self.prompt = ""
        self.payload: dict = {}

    def complete_json(self, *, prompt: str, payload: dict) -> dict:  # noqa: ARG002
        self.prompt = prompt
        self.payload = payload
        return {"result": self.result}


def test_hunt_mode_forbids_project_identifiers_in_the_prompt(monkeypatch: pytest.MonkeyPatch) -> None:
    spy = _Spy({"include": ["extractall\\("]})
    monkeypatch.setattr(backtest.LLMRouter, "provider_for", lambda self, profile: spy)
    out = backtest.build_hunt_rule(PATTERN)
    assert out["mode"] == "hunt"
    assert "禁止出现只属于某个项目的标识符" in spy.prompt
    assert "target_file_hint" not in spy.payload


def test_backtest_mode_still_passes_the_target_file(monkeypatch: pytest.MonkeyPatch) -> None:
    spy = _Spy({"include": ["O_TRUNC"]})
    monkeypatch.setattr(backtest.LLMRouter, "provider_for", lambda self, profile: spy)
    backtest.build_rule(PATTERN, "src/filelock/_unix.py")
    assert spy.payload["target_file_hint"] == "src/filelock/_unix.py"


def test_long_identifiers_surface_name_bound_rules() -> None:
    assert backtest.long_identifiers({"include": ["_find_fastapi_validator"]}) == ["_find_fastapi_validator"]
    # 这个启发式是**粗的**: 通用常量 O_NOFOLLOW 也会被列出来 —— 它只负责"摆出来给人看",
    # 不负责判定, 所以测试锁的是"长 token 会被列出", 不是"只列私有名字"。
    assert backtest.long_identifiers({"include": ["os\\.open\\("]}) == []
    assert backtest.long_identifiers({"exclude": ["O_NOFOLLOW"]}) == ["O_NOFOLLOW"]


# ---------------------------------------------------------------- 多采样取并集

def test_identical_rules_are_deduplicated(monkeypatch: pytest.MonkeyPatch) -> None:
    same = {"status": "ok", "rule": {"path_glob": "*.py", "include": ["x"]}, "long_identifiers": []}
    other = {"status": "ok", "rule": {"path_glob": "*.py", "include": ["y"]}, "long_identifiers": ["y_long_name"]}
    seq = [same, same, other]
    monkeypatch.setattr(backtest, "build_hunt_rule", lambda pattern, glob="": seq.pop(0))
    out = backtest.build_hunt_rules(PATTERN, "*.py", samples=3)
    assert out["status"] == "ok"
    assert out["samples_used"] == 2          # 重复的那条被丢掉
    assert out["long_identifiers"] == ["y_long_name"]


def test_no_rule_at_all_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(backtest, "build_hunt_rule", lambda pattern, glob="": {"status": "error", "reason": "坏"})
    out = backtest.build_hunt_rules(PATTERN, "*.py", samples=2)
    assert out["status"] == "error"


def test_the_union_ranks_by_how_many_rules_hit(monkeypatch: pytest.MonkeyPatch) -> None:
    """被两条规则同时圈中的文件排在只有一条规则命中的前面。"""
    results = [
        {"status": "ok", "files_scanned": 10, "candidates": ["a.py", "tarfile.py"]},
        {"status": "ok", "files_scanned": 12, "candidates": ["tarfile.py", "b.py"]},
    ]
    monkeypatch.setattr(backtest, "scan", lambda *a, **kw: results.pop(0))
    out = backtest.scan_many(1, [
        {"path_glob": "*.py", "include": ["x"]},
        {"path_glob": "*.py", "include": ["y"]},
    ], ["tarfile.py"])
    assert out["candidates"][0] == "tarfile.py"      # 2 票, 第一
    assert out["target_hit"] is True and out["target_rank"] == 1
    assert out["votes"]["tarfile.py"] == 2


def test_one_broken_rule_does_not_kill_the_union(monkeypatch: pytest.MonkeyPatch) -> None:
    results = [
        {"status": "error", "reason": "超时"},
        {"status": "ok", "files_scanned": 3, "candidates": ["tarfile.py"]},
    ]
    monkeypatch.setattr(backtest, "scan", lambda *a, **kw: results.pop(0))
    out = backtest.scan_many(1, [{"path_glob": "*.py", "include": ["x"]},
                                 {"path_glob": "*.py", "include": ["y"]}], ["tarfile.py"])
    assert out["status"] == "ok"
    assert out["target_hit"] is True
    assert out["failures"] == ["超时"]
