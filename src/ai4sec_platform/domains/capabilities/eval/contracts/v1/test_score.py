#!/usr/bin/env python3
"""判分脚本 v1 的自测 —— 全部用假答卷，不需要工具、不需要容器、不联网。

    python3 test_score.py            # 标准 unittest 输出
    python3 test_score.py -v         # 逐条
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import score


FILE = "a/b/C.java"


def truth(variant: str = "pre", sid: str = "s_0001") -> dict:
    return {
        "sample_id": sid,
        "case_id": 123,
        "canonical_id": "CVE-2026-78162",
        "variant": variant,
        "gt": {"file": FILE, "function": "doStart",
               "line_start": 343, "line_end": 345, "cwe": "CWE-502"},
        # 补丁里另有 300-320 与 400-410 两个 hunk
        "patch_hunks": [[300, 320], [343, 345], [400, 410]],
        "valid_until": "2027-04-30",
    }


def answer(*findings, found=None, **extra) -> dict:
    payload = {"found": bool(findings) if found is None else found,
               "findings": list(findings)}
    payload.update(extra)
    return payload


def find(start: int, end: int, *, file: str = FILE, func: str = "doStart",
         cwe: str = "CWE-502") -> dict:
    return {"file": file, "function": func, "line_start": start,
            "line_end": end, "type_cwe": cwe, "evidence": "stub"}


class TestGrades(unittest.TestCase):
    """契约 §4.1 的四级标签。"""

    def judge(self, *findings, found=None):
        return score.judge_sample(answer(*findings, found=found), truth()).label

    def test_exact_range_is_strict_hit(self):
        self.assertEqual(self.judge(find(343, 345)), "strict_hit")

    def test_partial_overlap_is_strict_hit(self):
        self.assertEqual(self.judge(find(340, 344)), "strict_hit")
        self.assertEqual(self.judge(find(345, 360)), "strict_hit")

    def test_same_function_nearby_is_near_hit(self):
        self.assertEqual(self.judge(find(346, 348)), "near_hit")

    def test_near_hit_boundary_15_counts(self):
        # 345 -> 360：行距正好 15，算命中
        self.assertEqual(self.judge(find(360, 361)), "near_hit")

    def test_gap_16_is_not_near_hit(self):
        # 行距 16，且不落在其他 hunk 内 -> 漏报
        self.assertEqual(self.judge(find(361, 362)), "miss")

    def test_different_function_is_not_near_hit(self):
        self.assertEqual(self.judge(find(346, 348, func="other")), "miss")

    def test_other_hunk_is_its_own_label(self):
        self.assertEqual(self.judge(find(305, 306, func="other")), "other_hunk")
        self.assertEqual(self.judge(find(400, 410)), "other_hunk")

    def test_wrong_file_is_miss(self):
        self.assertEqual(self.judge(find(343, 345, file="a/b/Other.java")), "miss")

    def test_wrong_file_does_not_fall_into_other_hunk(self):
        self.assertEqual(self.judge(find(305, 306, file="a/b/Other.java")), "miss")

    def test_best_label_wins(self):
        # 一条 near_hit + 一条 strict_hit，取最高级
        self.assertEqual(self.judge(find(346, 348), find(343, 345)), "strict_hit")

    def test_empty_answer_is_miss(self):
        self.assertEqual(self.judge(found=False), "miss")

    def test_post_sample_found_is_false_positive(self):
        payload = answer(find(343, 345))
        self.assertEqual(score.judge_sample(payload, truth("post")).label,
                         "false_positive")

    def test_post_sample_clean_is_true_negative(self):
        payload = answer(found=False)
        self.assertEqual(score.judge_sample(payload, truth("post")).label,
                         "true_negative")

    def test_more_than_five_findings_are_truncated(self):
        # 第 6 条才是对的 -> 被截断 -> 漏报，且 detail 写清截断
        noise = [find(1, 2, func="x") for _ in range(5)]
        row = score.judge_sample(answer(*noise, find(343, 345)), truth())
        self.assertEqual(row.label, "miss")
        self.assertIn("截断", row.detail)


class TestValidation(unittest.TestCase):
    """契约 §3.1 / schema 一致性。"""

    def errors(self, payload):
        return score.validate_answer(payload)

    def test_valid_answer_passes(self):
        self.assertEqual(self.errors(answer(find(343, 345))), [])

    def test_found_false_with_findings_rejected(self):
        self.assertTrue(self.errors(answer(find(343, 345), found=False)))

    def test_found_true_without_findings_rejected(self):
        self.assertTrue(self.errors(answer(found=True)))

    def test_extra_top_level_field_rejected(self):
        self.assertTrue(self.errors(answer(find(343, 345), confidence=0.9)))

    def test_extra_finding_field_rejected(self):
        bad = find(343, 345)
        bad["score"] = 0.8
        self.assertTrue(self.errors(answer(bad)))

    def test_line_end_before_start_rejected(self):
        self.assertTrue(self.errors(answer(find(350, 340))))

    def test_zero_line_rejected(self):
        self.assertTrue(self.errors(answer(find(0, 5))))

    def test_bad_cwe_rejected(self):
        self.assertTrue(self.errors(answer(find(343, 345, cwe="502"))))

    def test_missing_file_rejected(self):
        bad = find(343, 345)
        bad.pop("file")
        self.assertTrue(self.errors(answer(bad)))

    def test_non_object_rejected(self):
        self.assertTrue(self.errors(["not", "an", "object"]))

    def test_missing_answer_file_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            answers = Path(tmp) / "answers"
            answers.mkdir()
            rep = score.score_repeat({}, {"s_0001": truth()})
            self.assertEqual(rep["labels"]["invalid_output"], 1)
            self.assertEqual(rep["n"]["positives"], 0)
            self.assertIsNone(rep["locate_rate"]["value"])


class TestMetrics(unittest.TestCase):

    def test_wilson_matches_textbook(self):
        lo, hi = score.wilson(10, 20)
        self.assertAlmostEqual(lo, 0.2993, places=3)
        self.assertAlmostEqual(hi, 0.7007, places=3)

    def test_wilson_zero_denominator_returns_none(self):
        self.assertIsNone(score.wilson(0, 0))

    def test_balanced_accuracy_formula(self):
        rows = [score.Row("s1", "pre", "strict_hit"),
                score.Row("s2", "pre", "miss"),
                score.Row("s3", "post", "false_positive"),
                score.Row("s4", "post", "true_negative")]
        m = score.metrics(rows)
        # locate = 1/2, fp = 1/2 -> bal = (0.5 + 0.5)/2 = 0.5
        self.assertEqual(m["locate_rate"]["value"], 0.5)
        self.assertEqual(m["false_positive_rate"]["value"], 0.5)
        self.assertEqual(m["balanced_accuracy"]["value"], 0.5)

    def test_near_hit_counts_in_locate_but_not_strict(self):
        rows = [score.Row("s1", "pre", "near_hit"),
                score.Row("s2", "pre", "miss")]
        m = score.metrics(rows)
        self.assertEqual(m["locate_rate"]["value"], 0.5)
        self.assertEqual(m["strict_locate_rate"]["value"], 0.0)

    def test_invalid_excluded_from_denominator(self):
        rows = [score.Row("s1", "pre", "strict_hit"),
                score.Row("s2", "pre", "invalid_output")]
        m = score.metrics(rows)
        self.assertEqual(m["locate_rate"]["n"], 1)
        self.assertEqual(m["locate_rate"]["value"], 1.0)
        self.assertEqual(m["invalid_output"]["rate"], 0.5)

    def test_aggregate_marks_identical_repeats(self):
        rows = [score.Row("s1", "pre", "strict_hit"),
                score.Row("s2", "pre", "miss")]
        agg = score.aggregate([score.metrics(rows) for _ in range(3)])
        self.assertTrue(agg["locate_rate"]["identical"])
        self.assertEqual(agg["locate_rate"]["median"], 0.5)
        self.assertEqual(agg["locate_rate"]["values"], [0.5, 0.5, 0.5])

    def test_aggregate_detects_variance(self):
        a = score.metrics([score.Row("s1", "pre", "strict_hit"),
                           score.Row("s2", "pre", "miss")])
        b = score.metrics([score.Row("s1", "pre", "miss"),
                           score.Row("s2", "pre", "miss")])
        agg = score.aggregate([a, b])
        self.assertFalse(agg["locate_rate"]["identical"])
        self.assertEqual(agg["locate_rate"]["min"], 0.0)
        self.assertEqual(agg["locate_rate"]["max"], 0.5)


class TestEndToEnd(unittest.TestCase):
    """走真实目录结构：truth/ + answers/r1..r3/。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.truth_dir = root / "truth"
        self.answers_dir = root / "answers"
        self.truth_dir.mkdir()

        samples = {
            "s_0001": (truth("pre", "s_0001"), answer(find(343, 345))),      # strict
            "s_0002": (truth("pre", "s_0002"), answer(find(346, 348))),      # near
            "s_0003": (truth("pre", "s_0003"), answer(found=False)),         # miss
            "s_0004": (truth("post", "s_0004"), answer(found=False)),        # tn
            "s_0005": (truth("post", "s_0005"), answer(find(343, 345))),     # fp
            "s_0006": (truth("pre", "s_0006"), answer(["bad"])),             # invalid
        }
        for sid, (meta, ans) in samples.items():
            (self.truth_dir / f"{sid}.json").write_text(
                json.dumps(meta, ensure_ascii=False), encoding="utf-8")
            for r in ("r1", "r2", "r3"):
                (self.answers_dir / r).mkdir(parents=True, exist_ok=True)
                (self.answers_dir / r / f"{sid}.json").write_text(
                    json.dumps(ans, ensure_ascii=False), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_report_numbers(self):
        rep = score.build_report(self.answers_dir, self.truth_dir)
        self.assertEqual(rep["contract_version"], "v1")
        self.assertEqual(len(rep["repeats"]), 3)
        self.assertEqual(rep["adaptation_verdict"], "ok")

        first = rep["per_repeat"]["r1"]
        self.assertEqual(first["n"], {"positives": 3, "negatives": 2, "total": 6})
        # 正样本：1 strict + 1 near + 1 miss（invalid 不计分母）
        self.assertEqual(first["labels"]["strict_hit"], 1)
        self.assertEqual(first["labels"]["near_hit"], 1)
        self.assertEqual(first["labels"]["miss"], 1)
        self.assertEqual(first["labels"]["invalid_output"], 1)
        self.assertEqual(first["locate_rate"]["value"], round(2 / 3, 4))
        self.assertEqual(first["strict_locate_rate"]["value"], round(1 / 3, 4))
        self.assertEqual(first["false_positive_rate"]["value"], 0.5)

        self.assertTrue(rep["aggregate"]["locate_rate"]["identical"])
        self.assertEqual(rep["aggregate"]["locate_rate"]["median"], round(2 / 3, 4))

    def test_caveats_always_present(self):
        rep = score.build_report(self.answers_dir, self.truth_dir)
        self.assertGreaterEqual(len(rep["caveats"]), 5)

    def test_all_invalid_is_unable_to_adapt(self):
        for r in ("r1", "r2", "r3"):
            for path in (self.answers_dir / r).glob("*.json"):
                path.write_text('["bad"]', encoding="utf-8")
        rep = score.build_report(self.answers_dir, self.truth_dir)
        self.assertEqual(rep["adaptation_verdict"], "unable_to_adapt")

    def test_summary_contains_numbers_and_caveats(self):
        text = score.format_summary(score.build_report(self.answers_dir, self.truth_dir))
        self.assertIn("locate_rate", text)
        self.assertIn("caveats", text)
        self.assertIn("LLM 成分", text)


class TestReportContract(unittest.TestCase):
    """PRD §8 把 n_samples / window 写进了 reports 表的 CHECK：缺了这条报表就落不了库。"""

    def test_window_from_published_at(self):
        truth = {"s_0001": {"published_at": "2026-10-20"},
                 "s_0002": {"published_at": "2026-09-01"},
                 "s_0003": {"valid_until": "2027-04-30"}}
        window = score.sample_window(truth)
        self.assertEqual(window["published_at_from"], "2026-09-01")
        self.assertEqual(window["published_at_to"], "2026-10-20")
        self.assertEqual(window["valid_until_min"], "2027-04-30")
        # 有一条没有日期 —— 窗口是拿 2/3 算的，必须写出来
        self.assertEqual(window["samples_without_published_at"], 1)

    def test_window_without_dates_is_null_not_empty(self):
        window = score.sample_window({"s_0001": {"variant": "pre"}})
        self.assertIsNone(window["published_at_from"])
        self.assertIsNone(window["published_at_to"])
        self.assertEqual(window["samples_without_published_at"], 1)

    def test_report_carries_both_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "truth").mkdir()
            (root / "answers").mkdir()
            meta = truth()
            meta["published_at"] = "2026-10-20"
            (root / "truth" / "s_0001.json").write_text(
                json.dumps(meta, ensure_ascii=False), encoding="utf-8")
            (root / "answers" / "s_0001.json").write_text(
                json.dumps(answer(find(343, 345))), encoding="utf-8")

            rep = score.build_report(root / "answers", root / "truth")
            self.assertEqual(rep["n_samples"], 1)
            self.assertEqual(rep["window"]["published_at_from"], "2026-10-20")
            # 两个键都要能被 json_extract 取到，且非 null
            self.assertIsNotNone(json.loads(json.dumps(rep))["window"])
            # 样本数/时间窗必须按这批样本 real 的数写，不是计划里的 200 条
            coverage = rep["caveats"][2]
            self.assertIn("1 个样本", coverage)
            self.assertIn("2026-10-20", coverage)
            self.assertNotIn("200", coverage)


class TestSchemaParity(unittest.TestCase):
    """validate_answer 与 class1_llm_audit.schema.json 必须同口 —— 单一事实来源不许漂。"""

    CASES = {
        "hit": answer(find(343, 345)),
        "clean": answer(found=False),
        "conflict": answer(find(343, 345), found=False),
        "empty_true": answer(found=True),
        "extra_top": answer(find(343, 345), confidence=0.9),
        "bad_cwe": answer(find(343, 345, cwe="502")),
    }

    def test_builtin_matches_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema 未安装")
        schema_path = Path(__file__).with_name("class1_llm_audit.schema.json")
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        validator = jsonschema.Draft202012Validator(schema)
        for name, payload in self.CASES.items():
            builtin_ok = not score.validate_answer(payload)
            schema_ok = not list(validator.iter_errors(payload))
            self.assertEqual(builtin_ok, schema_ok,
                             f"{name}: 内置校验={builtin_ok} schema={schema_ok}")


class TestExcluded(unittest.TestCase):
    """D4-5：工具自报「这类样本我不覆盖」的样本，不进分母、也不算 invalid_output。

    这一组锁的是"**没覆盖 ≠ 没找到**"。它比多算一条命中更重要：算错命中率只是数字偏一点，
    把语言不支持记成 miss 是给工具扣了一个它没被问过的问题的分。
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.truth_dir = root / "truth"
        self.answers_dir = root / "answers"
        self.truth_dir.mkdir()
        samples = {
            "s_0001": (truth("pre", "s_0001"), answer(find(343, 345))),   # strict
            "s_0002": (truth("pre", "s_0002"), answer(found=False)),      # miss
            "s_0003": (truth("pre", "s_0003"), None),                     # 语言不支持
        }
        for sid, (meta, ans) in samples.items():
            (self.truth_dir / f"{sid}.json").write_text(
                json.dumps(meta, ensure_ascii=False), encoding="utf-8")
            if ans is None:
                continue
            for r in ("r1", "r2"):
                (self.answers_dir / r).mkdir(parents=True, exist_ok=True)
                (self.answers_dir / r / f"{sid}.json").write_text(
                    json.dumps(ans, ensure_ascii=False), encoding="utf-8")
        self.write_manifest("r1", {"s_0003": "language_not_supported"})
        self.write_manifest("r2", {"s_0003": "language_not_supported"})

    def write_manifest(self, repeat: str, payload: dict, base: Path | None = None) -> None:
        target = (base or self.answers_dir / repeat)
        target.mkdir(parents=True, exist_ok=True)
        (target / score.EXCLUDED_MANIFEST).write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_excluded_leaves_denominator(self):
        rep = score.build_report(self.answers_dir, self.truth_dir)
        first = rep["per_repeat"]["r1"]
        # 分母只剩两条正样本；被排除的那条既不进 positives 也不算 invalid
        self.assertEqual(first["n"]["positives"], 2)
        self.assertEqual(first["n"]["excluded"], 1)
        self.assertEqual(first["n"]["total"], 2)
        self.assertEqual(first["labels"]["invalid_output"], 0)
        self.assertEqual(first["labels"]["excluded"], 1)
        self.assertEqual(first["locate_rate"]["value"], 0.5)
        self.assertEqual(first["locate_rate"]["n"], 2)

    def test_excluded_is_not_a_missing_answer(self):
        rep = score.build_report(self.answers_dir, self.truth_dir)
        self.assertEqual(rep["answers_missing"], [])
        self.assertEqual(rep["n_excluded"], 1)
        self.assertEqual(rep["excluded_reasons"], {"language_not_supported": 1})

    def test_caveat_names_the_excluded_count(self):
        rep = score.build_report(self.answers_dir, self.truth_dir)
        joined = "\n".join(rep["caveats"])
        self.assertIn("1 条", joined)
        self.assertIn("未计入分母", joined)

    def test_invalid_rate_uses_scored_denominator(self):
        # 一份坏答卷 + 一条被排除：invalid 率按 2 条算(0.5)，不是按 3 条算(0.33)
        (self.answers_dir / "r1" / "s_0002.json").write_text('["bad"]', encoding="utf-8")
        rep = score.build_report(self.answers_dir, self.truth_dir)
        inv = rep["per_repeat"]["r1"]["invalid_output"]
        self.assertEqual((inv["k"], inv["n"]), (1, 2))

    def test_manifest_is_not_read_as_an_answer(self):
        rep = score.build_report(self.answers_dir, self.truth_dir)
        self.assertEqual(sorted(rep["per_repeat"]["r1"]), sorted(
            ["labels", "n", "locate_rate", "strict_locate_rate",
             "false_positive_rate", "balanced_accuracy", "invalid_output",
             "excluded", "samples"]))
        self.assertNotIn(score.EXCLUDED_MANIFEST, rep["per_repeat"]["r1"]["samples"])

    def test_no_manifest_keeps_old_numbers(self):
        # 删掉清单 = 回到 v1 的口径：那条样本变成"缺答卷"
        for r in ("r1", "r2"):
            (self.answers_dir / r / score.EXCLUDED_MANIFEST).unlink()
        rep = score.build_report(self.answers_dir, self.truth_dir)
        self.assertEqual(rep["n_excluded"], 0)
        self.assertEqual(rep["per_repeat"]["r1"]["labels"]["invalid_output"], 1)
        self.assertEqual(rep["answers_missing"], ["s_0003"])

    def test_flat_layout_manifest(self):
        tmp = Path(self.tmp.name) / "flat"
        (tmp / "answers").mkdir(parents=True)
        for sid in ("s_0001", "s_0002"):
            (tmp / "answers" / f"{sid}.json").write_text(
                json.dumps(answer(find(343, 345)), ensure_ascii=False), encoding="utf-8")
        self.write_manifest("", {"s_0003": "language_not_supported"}, base=tmp / "answers")
        rep = score.build_report(tmp / "answers", self.truth_dir)
        self.assertEqual(rep["repeats"], ["r1"])
        self.assertEqual(rep["n_excluded"], 1)

    def test_broken_manifest_fails_loudly(self):
        (self.answers_dir / "r1" / score.EXCLUDED_MANIFEST).write_text(
            '{"s_0003": ""}', encoding="utf-8")
        with self.assertRaises(SystemExit) as ctx:
            score.build_report(self.answers_dir, self.truth_dir)
        self.assertIn("原因", str(ctx.exception))

    def test_manifest_pointing_at_an_unknown_sample_fails(self):
        """样本 id 写错会让排除静默失效: 清单看着写了, 那条照样被算成 invalid_output。"""
        self.write_manifest("r1", {"s_3": "language_not_supported"})
        with self.assertRaises(SystemExit) as ctx:
            score.build_report(self.answers_dir, self.truth_dir)
        self.assertIn("真值里没有", str(ctx.exception))

    def test_excessive_exclusion_is_called_out(self):
        # 3 条样本排除 2 条(67%)：分数只能说明剩下那条
        self.write_manifest("r1", {"s_0001": "language_not_supported",
                                   "s_0002": "language_not_supported"})
        self.write_manifest("r2", {"s_0001": "language_not_supported",
                                   "s_0002": "language_not_supported"})
        rep = score.build_report(self.answers_dir, self.truth_dir)
        joined = "\n".join(rep["caveats"])
        self.assertIn("不能代表该工具的整体能力", joined)

    def test_answer_and_exclusion_together_is_flagged(self):
        (self.answers_dir / "r1" / "s_0003.json").write_text(
            json.dumps(answer(found=False)), encoding="utf-8")
        rep = score.build_report(self.answers_dir, self.truth_dir)
        row = next(r for r in rep["per_repeat"]["r1"]["samples"] if r["sample_id"] == "s_0003")
        self.assertEqual(row["label"], "excluded")
        self.assertIn("同时存在答卷文件", row["detail"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
