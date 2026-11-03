"""E1 存取层: 样本落库、答卷收件、判分与报表。

用例按"哪一种谎"组织:
  · 数据集目录被人动过, 却照样落库(哈希核对)
  · 同一份数据集重跑一遍, 样本翻倍(幂等)
  · 三轮回不一样, 却被压成一个好看的标签(抖动必须照实写)
  · 判分重算一次, 库里留下两套结论(先删后写)
  · 答卷还没到就判分, 出来一份 0 样本的报表(必须拒)
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities.eval import samples as S
from ai4sec_platform.domains.capabilities.eval import store

DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 alpha
 beta
-VULN(x)
+SAFE(x)
+also_safe(x)
 gamma
 delta
"""
POST = "alpha\nbeta\nSAFE(x)\nalso_safe(x)\ngamma\ndelta"


def _source(case_id: int, repo: str, **over) -> S.CaseSource:
    base = dict(
        case_id=case_id, canonical_id=f"CVE-2026-{1000 + case_id}", repo=repo,
        commit_sha=str(case_id) * 40, file_path="app.py", function="handler",
        line_start=3, line_end=3, cwe="CWE-78", published_at="2026-10-20",
        vuln_content="VULN(x)", patch_diff=DIFF,
    )
    base.update(over)
    return S.CaseSource(**base)


def _fetcher(post: str | None = POST):
    return lambda repo, ref, path: post


@pytest.fixture()
def conn() -> sqlite3.Connection:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    init_db(c)
    return c


def _dataset(tmp_path: Path, pairs: int = 1) -> Path:
    sources = [_source(i + 1, f"acme/r{i + 1}") for i in range(pairs)]
    S.build_dataset(sources, _fetcher(), tmp_path / "ds", limit=pairs)
    return tmp_path / "ds"


def _answer_pre(line_start: int = 3) -> str:
    return json.dumps({"found": True, "findings": [{
        "file": "app.py", "function": "handler", "line_start": line_start,
        "line_end": line_start, "type_cwe": "CWE-78", "evidence": "stub"}]})


CLEAN = json.dumps({"found": False, "findings": []})


class TestIngest:
    def test_writes_both_variants_of_a_pair(self, conn, tmp_path):
        report = store.ingest_dataset(conn, _dataset(tmp_path))
        assert report["samples"] == 2 and report["pairs"] == 1
        assert report["inserted"] == 2 and report["skipped"] == 0

        rows = store.list_samples(conn)
        assert {r["polarity"] for r in rows} == {"pre", "post"}
        assert {r["pair_key"] for r in rows} == {"case-1"}
        pre = next(r for r in rows if r["polarity"] == "pre")
        assert pre["gt"]["line_start"] == 3
        assert pre["published_at"] == "2026-10-20"

    def test_rerun_updates_instead_of_duplicating(self, conn, tmp_path):
        ds = _dataset(tmp_path)
        store.ingest_dataset(conn, ds)
        again = store.ingest_dataset(conn, ds)
        assert again["inserted"] == 0 and again["updated"] == 2
        assert conn.execute("SELECT COUNT(*) FROM capability_eval_samples").fetchone()[0] == 2

    def test_tampered_artifact_is_refused(self, conn, tmp_path):
        # 目录被改过 -> 哈希对不上。此时落库等于给一份不知道是什么的代码出结论
        ds = _dataset(tmp_path)
        code = next((ds / "samples").glob("*/code.py"))
        code.write_text(code.read_text(encoding="utf-8") + "\n# tampered\n", encoding="utf-8")
        report = store.ingest_dataset(conn, ds)
        assert report["samples"] == 1
        assert report["skips"][0]["reason"] == "artifact_hash_mismatch"

    def test_missing_truth_dir_is_an_error_not_an_empty_dataset(self, conn, tmp_path):
        (tmp_path / "empty").mkdir()
        with pytest.raises(ValueError):
            store.ingest_dataset(conn, tmp_path / "empty")


class TestRuns:
    def test_unknown_category_is_refused(self, conn):
        with pytest.raises(ValueError):
            store.create_run(conn, item_id=1, category="nope")

    def test_zero_repeats_is_refused(self, conn):
        with pytest.raises(ValueError):
            store.create_run(conn, item_id=1, repeats=0)

    def test_new_run_is_running(self, conn):
        rid = store.create_run(conn, item_id=1, tool_version="abc")
        run = store.get_run(conn, rid)
        assert run["status"] == "running" and run["report"] is None

    def test_finish_rejects_unknown_status_and_reason(self, conn):
        rid = store.create_run(conn, item_id=1)
        with pytest.raises(ValueError):
            store.finish_run(conn, rid, "finished")
        with pytest.raises(ValueError):
            store.finish_run(conn, rid, "failed", failure_reason="看不懂")

    def test_budget_smaller_than_the_workload_is_refused_before_starting(self, conn, tmp_path):
        """2 个样本 × 3 轮 = 6 次调用, 预算 5 —— 注定跑不完。

        必须**开跑前**拒绝: 跑到一半被预算掐断, 库里会留下一条 budget_exceeded 终态,
        而那条记录看起来像"工具不行", 实际是运营参数配错了。
        """
        store.ingest_dataset(conn, _dataset(tmp_path))
        with pytest.raises(ValueError, match="预算不够"):
            store.create_run(conn, item_id=1, repeats=3, budget={"max_model_calls": 5})
        assert conn.execute("SELECT COUNT(*) FROM capability_eval_runs").fetchone()[0] == 0

        # 够的时候正常开
        rid = store.create_run(conn, item_id=1, repeats=3, budget={"max_model_calls": 6})
        assert store.get_run(conn, rid)["budget_json"]["max_model_calls"] == 6

    def test_latest_recipe_ignores_superseded_versions(self, conn):
        conn.execute(
            "INSERT INTO capability_eval_recipes (item_id, category, tool_version, recipe_json,"
            " verified_at, superseded_by, created_at) VALUES (1,?,'v1','{\"invoke\":1}',"
            "'2026-11-01T00:00:00Z',2,'2026-11-01T00:00:00Z')",
            (store.CATEGORY_CLASS1,))
        conn.execute(
            "INSERT INTO capability_eval_recipes (item_id, category, tool_version, recipe_json,"
            " verified_at, created_at) VALUES (1,?,'v2','{\"invoke\":2}','2026-11-02T00:00:00Z',"
            "'2026-11-02T00:00:00Z')", (store.CATEGORY_CLASS1,))
        conn.commit()
        latest = store.latest_recipe(conn, 1)
        assert latest["tool_version"] == "v2" and latest["recipe"] == {"invoke": 2}


class TestAnswers:
    def _setup(self, conn, tmp_path):
        store.ingest_dataset(conn, _dataset(tmp_path))
        rid = store.create_run(conn, item_id=1, repeats=3)
        keys = [s["sample_key"] for s in store.list_samples(conn)]
        return rid, keys

    def test_unknown_sample_is_reported_not_silently_dropped(self, conn, tmp_path):
        rid, keys = self._setup(conn, tmp_path)
        out = store.save_answers(conn, rid, {keys[0]: [_answer_pre()], "s_9999": [CLEAN]})
        assert out["saved"] == 1 and out["unknown_samples"] == ["s_9999"]

    def test_extra_repeats_are_reported(self, conn, tmp_path):
        rid, keys = self._setup(conn, tmp_path)
        out = store.save_answers(conn, rid, {keys[0]: [CLEAN] * 4})
        assert out["saved"] == 3
        assert out["too_many_repeats"] == [{"sample": keys[0], "repeat_index": 3}]

    def test_missing_samples_are_listed(self, conn, tmp_path):
        rid, keys = self._setup(conn, tmp_path)
        out = store.save_answers(conn, rid, {keys[0]: [_answer_pre()]})
        assert keys[1] in out["missing_samples"]

    def test_delivery_keeps_raw_and_translated_apart(self, conn, tmp_path):
        """R8: 原生输出原样存; D3: 翻译结果另存一列, 判分读的是翻译结果。

        合并成一列会丢掉"工具到底说了什么" —— 而抽检翻译失真(D5)靠的就是那一列。
        """
        rid, keys = self._setup(conn, tmp_path)
        native = "SCAN OK: app.py:3 suspicious call\n(prose, not JSON)"
        store.save_answers(conn, rid, {keys[0]: [
            {"raw": native, "answer": _answer_pre()},
            {"raw": native, "answer": _answer_pre()},
            {"raw": native, "answer": _answer_pre()},
        ]})
        row = conn.execute(
            "SELECT raw_answer, answer_json FROM capability_eval_answers"
            " WHERE sample_id=(SELECT id FROM capability_eval_samples WHERE sample_key=?)"
            " ORDER BY repeat_index LIMIT 1", (keys[0],),
        ).fetchone()
        assert row["raw_answer"] == native            # 原样, 一个字都没改
        assert json.loads(row["answer_json"])["found"] is True   # 判分读的是这份

    def test_failed_translation_scores_invalid_output(self, conn, tmp_path):
        """parser 翻不出来 == invalid_output, 不能拿散文硬凑成 miss/true_negative。"""
        rid, keys = self._setup(conn, tmp_path)
        store.save_answers(conn, rid, {keys[0]: [{"raw": "some prose", "answer": None}] * 3})
        report = store.score_run(conn, rid)
        labels = {row["sample_id"]: row["label"]
                  for row in report["per_repeat"]["r1"]["samples"]}
        assert labels[keys[0]] == "invalid_output"
        # 原生输出仍然在库里, 可以回头查
        assert conn.execute("SELECT raw_answer FROM capability_eval_answers LIMIT 1").fetchone()[0] == "some prose"

    def test_raw_answer_is_stored_verbatim(self, conn, tmp_path):
        rid, keys = self._setup(conn, tmp_path)
        raw = '{ "found" : false ,  "findings" : [ ] }'
        store.save_answers(conn, rid, {keys[0]: [raw]})
        stored = conn.execute("SELECT raw_answer FROM capability_eval_answers").fetchone()[0]
        assert stored == raw  # 空格都不许动


class TestScoring:
    def _prepared(self, conn, tmp_path, pairs=1):
        store.ingest_dataset(conn, _dataset(tmp_path, pairs))
        rid = store.create_run(conn, item_id=1, repeats=3)
        rows = store.list_samples(conn)
        pre = next(r for r in rows if r["polarity"] == "pre")
        post = next(r for r in rows if r["polarity"] == "post")
        return rid, pre["sample_key"], post["sample_key"]

    def test_hit_and_true_negative(self, conn, tmp_path):
        rid, pre, post = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [_answer_pre()] * 3, post: [CLEAN] * 3})
        report = store.score_run(conn, rid)

        assert report["n_samples"] == 2
        assert report["window"]["published_at_from"] == "2026-10-20"
        assert report["aggregate"]["locate_rate"]["median"] == 1.0
        assert report["aggregate"]["false_positive_rate"]["median"] == 0.0

        results = {r["sample_key"]: r for r in store.get_results(conn, rid)}
        assert results[pre]["verdict"] == "strict_hit"
        assert results[pre]["location"] == "app.py:3-3"
        assert results[post]["verdict"] == "true_negative"

        run = store.get_run(conn, rid)
        assert run["status"] == "success" and run["caveats"]
        assert run["report"]["n_samples"] == 2

    def test_disagreeing_repeats_become_unstable(self, conn, tmp_path):
        rid, pre, post = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [_answer_pre(), _answer_pre(), CLEAN], post: [CLEAN] * 3})
        store.score_run(conn, rid)
        results = {r["sample_key"]: r for r in store.get_results(conn, rid)}
        assert results[pre]["verdict"] == "unstable"
        assert results[pre]["location"] == ""          # 多轮不一致时不挑一轮当代表
        labels = [x["label"] for x in results[pre]["per_repeat"]]
        assert labels == ["strict_hit", "strict_hit", "miss"]

    def test_undelivered_answer_is_invalid_output(self, conn, tmp_path):
        rid, pre, post = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [_answer_pre()] * 3})   # post 一条没交
        store.score_run(conn, rid)
        results = {r["sample_key"]: r for r in store.get_results(conn, rid)}
        assert results[post]["verdict"] == "invalid_output"

    def test_rescoring_leaves_one_set_of_conclusions(self, conn, tmp_path):
        rid, pre, post = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [_answer_pre()] * 3, post: [CLEAN] * 3})
        store.score_run(conn, rid)
        store.score_run(conn, rid)
        assert conn.execute("SELECT COUNT(*) FROM capability_eval_results").fetchone()[0] == 2
        assert conn.execute("SELECT COUNT(*) FROM capability_eval_reports").fetchone()[0] == 1

    def test_no_answers_at_all_is_refused(self, conn, tmp_path):
        rid, _, _ = self._prepared(conn, tmp_path)
        with pytest.raises(ValueError):
            store.score_run(conn, rid)

    def test_scoring_does_not_resurrect_a_failed_run(self, conn, tmp_path):
        rid, pre, post = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [_answer_pre()] * 3, post: [CLEAN] * 3})
        store.finish_run(conn, rid, "budget_exceeded", cost={"model_calls": 31})
        store.score_run(conn, rid)
        run = store.get_run(conn, rid)
        assert run["status"] == "budget_exceeded"
        assert run["cost_json"] == {"model_calls": 31}

    def test_report_lands_in_the_constrained_table(self, conn, tmp_path):
        rid, pre, post = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [_answer_pre()] * 3, post: [CLEAN] * 3})
        store.score_run(conn, rid)
        metrics = json.loads(conn.execute(
            "SELECT metrics_json FROM capability_eval_reports WHERE run_id=?", (rid,)).fetchone()[0])
        # 这两条是表的 CHECK 要求的; 缺了写不进去, 也就不会出现"看不出覆盖范围"的报表
        assert metrics["n_samples"] == 2
        assert metrics["window"] is not None


class TestExcluded:
    """D4-5: 工具自报「这类样本我不覆盖」时, 这条样本不进分母, 也不算跑失败。

    为什么值得单独一组用例: 20 对样本覆盖 17 种语言, 而被测工具往往只认其中几种。
    把"没覆盖"记成 invalid_output 或 miss, 分数就不是这个工具的水平, 而是"我们
    挑的样本有多适合它" —— 那是我们自己的口径问题, 不该记在它头上。
    """

    def _prepared(self, conn, tmp_path):
        store.ingest_dataset(conn, _dataset(tmp_path))
        rid = store.create_run(conn, item_id=1, repeats=3)
        rows = store.list_samples(conn)
        pre = next(r for r in rows if r["polarity"] == "pre")
        post = next(r for r in rows if r["polarity"] == "post")
        return rid, pre["sample_key"], post["sample_key"]

    @staticmethod
    def _excluded(reason: str = "language_not_supported") -> dict:
        # 这是 runner 交上来的第三种形态: 原生输出照留, 答案为空, 原因单列
        return {"raw": "shim: language_not_supported", "answer": None, "excluded": reason}

    def test_reason_lands_in_its_own_column(self, conn, tmp_path):
        rid, pre, _ = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [self._excluded()]})
        row = conn.execute(
            "SELECT answer_json, excluded_reason FROM capability_eval_answers").fetchone()
        assert row["excluded_reason"] == "language_not_supported"
        assert row["answer_json"] == ""          # 翻译失败与"不覆盖"在库里也必须分得开

    def test_empty_reason_is_not_an_exclusion(self, conn, tmp_path):
        """空串当排除会让一次漏填字段静默缩小分母 —— 必须落成 NULL。"""
        rid, pre, _ = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [{"raw": "x", "answer": None, "excluded": ""}]})
        assert conn.execute(
            "SELECT excluded_reason FROM capability_eval_answers").fetchone()[0] is None

    def test_excluded_sample_leaves_the_denominator(self, conn, tmp_path):
        rid, pre, post = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [self._excluded()] * 3, post: [CLEAN] * 3})
        report = store.score_run(conn, rid)

        assert report["n_samples"] == 2          # 这批样本一共几条
        assert report["n_excluded"] == 1         # 其中几条没进分母
        first = report["per_repeat"]["r1"]
        assert first["n"]["positives"] == 0      # 那条正样本不再算分母
        assert first["labels"]["invalid_output"] == 0
        assert report["answers_missing"] == []   # 被排除 ≠ 漏交

        results = {r["sample_key"]: r for r in store.get_results(conn, rid)}
        assert results[pre]["verdict"] == "excluded"
        assert results[post]["verdict"] == "true_negative"

    def test_exclusion_is_per_repeat(self, conn, tmp_path):
        """同一工具这轮不支持、那轮又支持(比如依赖刚好没装好)时, 合成一份就会说谎。"""
        rid, pre, post = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [self._excluded(), _answer_pre(), _answer_pre()],
                                       post: [CLEAN] * 3})
        report = store.score_run(conn, rid)
        assert report["per_repeat"]["r1"]["n"]["excluded"] == 1
        assert report["per_repeat"]["r2"]["n"].get("excluded", 0) == 0
        results = {r["sample_key"]: r for r in store.get_results(conn, rid)}
        # 一轮排除、两轮命中: 结论是不稳定, 不是命中也不是排除
        assert results[pre]["verdict"] == "unstable"

    def test_everything_excluded_still_scores(self, conn, tmp_path):
        """全部样本都不覆盖也是一个**必须如实报出来**的结果(分母 0), 不是"没跑"。"""
        rid, pre, post = self._prepared(conn, tmp_path)
        store.save_answers(conn, rid, {pre: [self._excluded()] * 3, post: [self._excluded()] * 3})
        report = store.score_run(conn, rid)
        assert report["n_excluded"] == 2
        assert report["aggregate"]["locate_rate"]["median"] is None
        assert "全部重复都无有效分母" in report["aggregate"]["locate_rate"]["note"]


class TestCategories:
    def test_empty_category_says_zero_not_missing(self, conn):
        cats = store.list_categories(conn)
        assert cats[0]["id"] == store.CATEGORY_CLASS1
        assert cats[0]["n_samples"] == 0 and cats[0]["n_runs"] == 0
