"""能力评测 E1 的五张表(PRD §8,2026-11-02)。

这些用例守的不是"表建出来了",而是**库自己会拒绝坏数据**的三处:
  · 报表里没有样本数/时间窗 —— 读者会自己脑补覆盖范围
  · caveats 是空白 —— 一份没有口径提醒的报表比没有报表更危险
  · 一对样本缺了 post —— 误报率的分母就没了,指标却照样算得出来
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from ai4sec_platform.db.models import init_db, reset_db

NOW = "2026-11-02T00:00:00Z"
GOOD_METRICS = {"n_samples": 40, "window": {"published_at_from": "2026-10-20"}}


@pytest.fixture()
def conn() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    init_db(c)
    return c


def _sample(conn, sid_suffix="0001", polarity="pre") -> None:
    conn.execute(
        "INSERT INTO capability_eval_samples (category, case_id, sample_key, pair_key, polarity,"
        " artifact_hash, artifact_path, ground_truth_json, published_at, valid_until, created_at)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        ("class1_llm_audit", 1, f"s_{sid_suffix}", "pair-0001", polarity, "a" * 64,
         f"samples/s_{sid_suffix}/code.py", json.dumps({"variant": polarity}),
         "2026-10-20", "2027-04-30", NOW),
    )


def _run(conn, **over) -> int:
    row = dict(item_id=47504, category="class1_llm_audit", tool_version="abc123",
               status="running", started_at=NOW, created_at=NOW)
    row.update(over)
    cols = ", ".join(row)
    marks = ", ".join("?" * len(row))
    cur = conn.execute(f"INSERT INTO capability_eval_runs ({cols}) VALUES ({marks})",
                       tuple(row.values()))
    return int(cur.lastrowid)


class TestTablesExist:
    def test_all_tables_are_created(self, conn):
        names = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        # 五张 + 原始答卷表(PRD §8 的五张里没有它, 但答卷到得比结论早)
        assert {"capability_eval_samples", "capability_eval_recipes",
                "capability_eval_runs", "capability_eval_answers",
                "capability_eval_results", "capability_eval_reports"} <= names

    def test_reset_db_drops_them(self, conn):
        reset_db(conn)
        names = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        # 先删后建 -> 表还在,但里面的数据没了
        assert "capability_eval_samples" in names
        assert conn.execute("SELECT COUNT(*) FROM capability_eval_samples").fetchone()[0] == 0


class TestSampleUniqueness:
    def test_pre_and_post_coexist(self, conn):
        _sample(conn, "0001", "pre")
        _sample(conn, "0002", "post")
        assert conn.execute("SELECT COUNT(*) FROM capability_eval_samples").fetchone()[0] == 2

    def test_second_pre_for_same_pair_is_rejected(self, conn):
        _sample(conn, "0001", "pre")
        with pytest.raises(sqlite3.IntegrityError):
            _sample(conn, "0003", "pre")

    def test_unknown_polarity_is_rejected(self, conn):
        with pytest.raises(sqlite3.IntegrityError):
            _sample(conn, "0001", "patched")


class TestRunsAndResults:
    def test_result_needs_a_run(self):
        # 用与 db.session.connect() 相同的姿势: PRAGMA 在任何写之前设。
        # PRAGMA foreign_keys 落在事务里是**静默空操作**(实测值仍是 0),所以
        # 这条必须先建连接再建表,不能复用模块级的 conn fixture。
        c = sqlite3.connect(":memory:")
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        init_db(c)
        _sample(c, "0001", "pre")
        sid = c.execute("SELECT id FROM capability_eval_samples").fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("INSERT INTO capability_eval_results (run_id, sample_id, verdict)"
                      " VALUES (?,?,'strict_hit')", (999, sid))

    def test_pragma_inside_a_transaction_is_a_silent_noop(self):
        # 这条不是测我们的表,是钉住"外键靠不住"的那个坑: 同一句 PRAGMA 写在写操作之后
        # 会静默失效,悬空引用照样插得进去。所以级联删除不能当成清理手段(见 cases.py
        # 里 delete_project 显式删关联行的做法),也解释了 08-20 那批孤儿行怎么来的。
        c = sqlite3.connect(":memory:")
        init_db(c)
        _sample(c, "0001", "pre")
        sid = c.execute("SELECT id FROM capability_eval_samples").fetchone()[0]
        c.execute("PRAGMA foreign_keys = ON")
        assert c.execute("PRAGMA foreign_keys").fetchone()[0] == 0
        c.execute("INSERT INTO capability_eval_results (run_id, sample_id, verdict)"
                  " VALUES (?,?,'strict_hit')", (999, sid))
        assert c.execute("SELECT COUNT(*) FROM capability_eval_results").fetchone()[0] == 1

    def test_one_result_per_sample_per_run(self, conn):
        _sample(conn, "0001", "pre")
        sid = conn.execute("SELECT id FROM capability_eval_samples").fetchone()[0]
        rid = _run(conn)
        conn.execute("INSERT INTO capability_eval_results (run_id, sample_id, verdict)"
                     " VALUES (?,?,'strict_hit')", (rid, sid))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO capability_eval_results (run_id, sample_id, verdict)"
                         " VALUES (?,?,'miss')", (rid, sid))

    def test_unknown_verdict_is_rejected(self, conn):
        _sample(conn, "0001", "pre")
        sid = conn.execute("SELECT id FROM capability_eval_samples").fetchone()[0]
        rid = _run(conn)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO capability_eval_results (run_id, sample_id, verdict)"
                         " VALUES (?,?,'hit')", (rid, sid))

    def test_unstable_is_an_allowed_verdict(self, conn):
        # 三轮不一致要能照实写库;用多数票或最好一轮来"收敛"才是造假
        _sample(conn, "0001", "pre")
        sid = conn.execute("SELECT id FROM capability_eval_samples").fetchone()[0]
        rid = _run(conn)
        conn.execute("INSERT INTO capability_eval_results (run_id, sample_id, verdict,"
                     " detail_json) VALUES (?,?,'unstable',?)",
                     (rid, sid, json.dumps({"per_repeat": ["strict_hit", "strict_hit", "miss"]})))
        assert conn.execute("SELECT verdict FROM capability_eval_results").fetchone()[0] == "unstable"

    def test_unknown_status_is_rejected(self, conn):
        with pytest.raises(sqlite3.IntegrityError):
            _run(conn, status="finished")

    def test_repeats_must_be_at_least_one(self, conn):
        with pytest.raises(sqlite3.IntegrityError):
            _run(conn, repeats=0)


class TestAnswers:
    def _ids(self, conn):
        _sample(conn, "0001", "pre")
        sid = conn.execute("SELECT id FROM capability_eval_samples").fetchone()[0]
        return _run(conn), sid

    def test_one_answer_per_repeat(self, conn):
        rid, sid = self._ids(conn)
        for i in range(3):
            conn.execute("INSERT INTO capability_eval_answers"
                         " (run_id, sample_id, repeat_index, raw_answer, created_at)"
                         " VALUES (?,?,?,?,?)", (rid, sid, i, "{}", NOW))
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO capability_eval_answers"
                         " (run_id, sample_id, repeat_index, raw_answer, created_at)"
                         " VALUES (?,?,?,?,?)", (rid, sid, 1, "{}", NOW))

    def test_negative_repeat_index_is_rejected(self, conn):
        rid, sid = self._ids(conn)
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO capability_eval_answers"
                         " (run_id, sample_id, repeat_index, raw_answer, created_at)"
                         " VALUES (?,?,?,?,?)", (rid, sid, -1, "{}", NOW))


class TestReportGuards:
    def _insert(self, conn, metrics, caveats="判据含 LLM 成分。"):
        rid = _run(conn, status="success")
        conn.execute("INSERT INTO capability_eval_reports (run_id, metrics_json, caveats,"
                     " created_at) VALUES (?,?,?,?)",
                     (rid, json.dumps(metrics), caveats, NOW))

    def test_good_report_is_accepted(self, conn):
        self._insert(conn, GOOD_METRICS)
        assert conn.execute("SELECT COUNT(*) FROM capability_eval_reports").fetchone()[0] == 1

    def test_missing_n_samples_is_rejected(self, conn):
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, {"window": {"published_at_from": "2026-10-20"}})

    def test_missing_window_is_rejected(self, conn):
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, {"n_samples": 40})

    def test_null_window_is_rejected(self, conn):
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, {"n_samples": 40, "window": None})

    def test_blank_caveats_is_rejected(self, conn):
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, GOOD_METRICS, caveats="   ")

    def test_one_report_per_run(self, conn):
        self._insert(conn, GOOD_METRICS)
        rid = conn.execute("SELECT run_id FROM capability_eval_reports").fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO capability_eval_reports (run_id, metrics_json, caveats,"
                         " created_at) VALUES (?,?,?,?)",
                         (rid, json.dumps(GOOD_METRICS), "另一份", NOW))


class TestExcludedMigration:
    """`excluded` 这个标签要进库, 需要动两处**旧库改不动**的地方(D4-5):

      · `capability_eval_answers` 缺一列 —— `ALTER TABLE ADD COLUMN` 能补;
      · `capability_eval_results.verdict` 的 CHECK 里没有它 —— CHECK 只能靠重建表。

    第二条最容易在"新建库跑得好好的、线上老库一写就炸"里漏掉, 所以这里用**旧表结构**
    建一次库, 再跑 init_db, 看它是不是真的补上了, 而且旧数据没丢。
    """

    OLD_RESULTS = """
    CREATE TABLE capability_eval_results (
        run_id      INTEGER NOT NULL,
        sample_id   INTEGER NOT NULL,
        verdict     TEXT NOT NULL CHECK (verdict IN (
                        'strict_hit', 'near_hit', 'other_hunk', 'miss',
                        'false_positive', 'true_negative', 'invalid_output', 'unstable')),
        location    TEXT NOT NULL DEFAULT '',
        detail_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail_json)),
        UNIQUE(run_id, sample_id)
    );
    CREATE TABLE capability_eval_answers (
        run_id       INTEGER NOT NULL,
        sample_id    INTEGER NOT NULL,
        repeat_index INTEGER NOT NULL CHECK (repeat_index >= 0),
        raw_answer   TEXT NOT NULL,
        answer_json  TEXT,
        created_at   TEXT NOT NULL,
        UNIQUE(run_id, sample_id, repeat_index)
    );
    INSERT INTO capability_eval_results VALUES (1, 1, 'strict_hit', 'a.py:3-3', '{}');
    INSERT INTO capability_eval_answers VALUES (1, 1, 0, 'raw', '{}', '2026-11-01T00:00:00Z');
    """

    def test_old_check_is_rebuilt_and_rows_survive(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(self.OLD_RESULTS)

        init_db(conn)   # 老库里跑一次: 建缺失的表 + 补列 + 重建 CHECK

        sql = conn.execute("SELECT sql FROM sqlite_master WHERE name='capability_eval_results'"
                           ).fetchone()[0]
        assert "'excluded'" in sql
        # 旧结论一条都不能少
        assert conn.execute("SELECT verdict FROM capability_eval_results").fetchone()[0] \
            == "strict_hit"
        # 新标签现在写得进去
        conn.execute("INSERT INTO capability_eval_results (run_id, sample_id, verdict)"
                     " VALUES (1, 2, 'excluded')")
        # 新列也在, 而且默认是 NULL(不是空串: 空串当排除会静默缩小分母)
        conn.execute("INSERT INTO capability_eval_answers (run_id, sample_id, repeat_index,"
                     " raw_answer, created_at) VALUES (2, 1, 0, 'raw', ?)", (NOW,))
        assert conn.execute(
            "SELECT excluded_reason FROM capability_eval_answers WHERE run_id=2").fetchone()[0] is None

    def test_init_db_is_idempotent_on_the_new_schema(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        init_db(conn)
        init_db(conn)   # 第二次不能因为"表已经重建过"再动一次
        assert conn.execute("SELECT COUNT(*) FROM capability_eval_results").fetchone()[0] == 0
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("INSERT INTO capability_eval_results (run_id, sample_id, verdict)"
                         " VALUES (1, 1, 'made_up')")
