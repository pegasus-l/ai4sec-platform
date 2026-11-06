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
        self.assertEqual(first["n"]["positives"], 3)
        self.assertEqual(first["n"]["negatives"], 2)
        self.assertEqual(first["n"]["total"], 6)
        # 6 条里 1 条 invalid_output，真正作答的是 5 条（v1.2 起单列）
        self.assertEqual(first["n"]["answered"], 5)
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
        # 2026-11-03 补：schema 曾把 function 写成 required，而 validate_answer 一直
        # 允许省（工具 finding 里常常没有函数名字段）。这四条锁住两边同口。
        "no_function": answer({"file": FILE, "line_start": 343, "line_end": 345}),
        "no_cwe": answer({"file": FILE, "function": "doStart",
                          "line_start": 343, "line_end": 345}),
        "function_null": answer({"file": FILE, "function": None,
                                 "line_start": 343, "line_end": 345}),
        "missing_line": answer({"file": FILE, "function": "doStart"}),
        # 2026-11-06 增补（v1.2）：两个可选诊断字段。两边必须同口，
        # 尤其是 found=true 与 no_answer 并存这条 —— 只写在 validate_answer 里、
        # 不写进 schema，就是判分脚本比契约更严，parser 按 schema 产出的答卷会被判废。
        "no_answer_clean": answer(found=False, no_answer="source_truncated"),
        "no_answer_conflict": answer(find(343, 345), no_answer="oops"),
        "no_answer_empty": answer(found=False, no_answer="  "),
        "limits_ok": answer(found=False, limits=["source_truncated"]),
        "limits_empty_item": answer(found=False, limits=[""]),
        "limits_not_list": answer(found=False, limits="source_truncated"),
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
             "excluded", "no_answer", "coverage", "limits",
             "silence_as_no_finding", "locator_fidelity", "samples"]))
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


class TestNoAnswer(unittest.TestCase):
    """X15（v1.2）：工具说「我给不出结论」时，答卷必须如实说，报表必须单列。

    这一组锁的是「沉默 ≠ 没找到」。老 shim 把"没答"翻译成 `{"found": false}`，
    于是正样本记漏报、负样本记真阴性 —— 两边的数都失真，而报表上没有任何一格会露馅。
    """

    def rows(self, limits=()):
        return [
            score.Row("s1", "pre", "strict_hit", limits=tuple(limits)),
            score.Row("s2", "pre", "no_answer", "source_truncated"),
            score.Row("s3", "post", "false_positive"),
            score.Row("s4", "post", "no_answer", "logic_review_inconclusive"),
        ]

    def test_label_and_reason_are_kept(self):
        row = score.judge_sample(answer(found=False, no_answer="source_truncated"),
                                 truth())
        self.assertEqual(row.label, "no_answer")
        self.assertEqual(row.detail, "source_truncated")

    def test_post_sample_silence_is_not_true_negative(self):
        # 负样本上沉默会在老口径里变成 100% 的"真阴性"，等于白送分数
        row = score.judge_sample(answer(found=False,
                                        no_answer="logic_review_inconclusive"),
                                 truth("post"))
        self.assertEqual(row.label, "no_answer")
        self.assertNotEqual(row.label, "true_negative")

    def test_present_takes_precedence_over_found_false(self):
        # 既带 no_answer 又带 found=false：记 no_answer，不记 miss
        row = score.judge_sample(answer(found=False, no_answer="static_scan_error"),
                                 truth())
        self.assertEqual(row.label, "no_answer")

    def test_leaves_main_denominator(self):
        m = score.metrics(self.rows())
        # 正样本 2 条里 1 条没答 -> 主分母 1；负样本同理
        self.assertEqual(m["locate_rate"]["n"], 1)
        self.assertEqual(m["locate_rate"]["value"], 1.0)
        self.assertEqual(m["false_positive_rate"]["n"], 1)
        self.assertEqual(m["false_positive_rate"]["value"], 1.0)
        # 没答的那条单独记账，不进 invalid_output
        self.assertEqual(m["no_answer"]["k"], 2)
        self.assertEqual(m["no_answer"]["rate"], 0.5)
        self.assertEqual(m["invalid_output"]["k"], 0)

    def test_answered_count_is_reported(self):
        m = score.metrics(self.rows())
        self.assertEqual(m["n"]["answered"], 2)
        self.assertEqual(m["coverage"]["answered"], 2)
        self.assertEqual(m["coverage"]["answered_rate"], 0.5)
        self.assertEqual(m["n"]["no_answer"], 2)

    def test_silence_as_no_finding_is_the_lower_bound(self):
        m = score.metrics(self.rows())
        legacy = m["silence_as_no_finding"]
        # 老口径：两条正样本里只有 1 条真命中 -> 0.5（主口径是 1.0）
        self.assertEqual(legacy["locate_rate"]["value"], 0.5)
        self.assertEqual(legacy["locate_rate"]["n"], 2)
        # 负样本：1 条误报 / 2 条 = 0.5（主口径是 1.0）
        self.assertEqual(legacy["false_positive_rate"]["value"], 0.5)
        self.assertEqual(legacy["false_positive_rate"]["n"], 2)

    def test_reasons_are_bucketed_not_concatenated(self):
        m = score.metrics(self.rows())
        self.assertEqual(m["no_answer"]["reasons"],
                         {"source_truncated": 1, "logic_review_inconclusive": 1})

    def test_limits_do_not_change_any_score(self):
        plain = score.metrics(self.rows())
        limited = score.metrics(self.rows(limits=("source_truncated",)))
        for key in ("locate_rate", "false_positive_rate", "balanced_accuracy"):
            self.assertEqual(plain[key]["value"], limited[key]["value"], key)
        # limits 只进覆盖面条目
        self.assertEqual(limited["limits"], {"source_truncated": 1})
        self.assertEqual(plain["limits"], {})


class TestNoAnswerReport(unittest.TestCase):
    """报表层：n_no_answer / n_answered / caveats / 摘要都要自己说清楚。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.truth_dir = root / "truth"
        self.answers_dir = root / "answers"
        self.truth_dir.mkdir()
        self.answers_dir.mkdir()
        samples = {
            "s_0001": (truth("pre", "s_0001"),
                       answer(find(343, 345), limits=["source_truncated"])),
            "s_0002": (truth("pre", "s_0002"),
                       answer(found=False, no_answer="source_truncated",
                              limits=["source_truncated"])),
            "s_0003": (truth("post", "s_0003"),
                       answer(found=False, no_answer="logic_review_inconclusive")),
        }
        for sid, (meta, ans) in samples.items():
            (self.truth_dir / f"{sid}.json").write_text(
                json.dumps(meta, ensure_ascii=False), encoding="utf-8")
            (self.answers_dir / f"{sid}.json").write_text(
                json.dumps(ans, ensure_ascii=False), encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_report_counts(self):
        rep = score.build_report(self.answers_dir, self.truth_dir)
        self.assertEqual(rep["n_no_answer"], 2)
        self.assertEqual(rep["n_answered"], 1)
        self.assertEqual(rep["no_answer_reasons"],
                         {"source_truncated": 1, "logic_review_inconclusive": 1})
        self.assertEqual(rep["coverage_limits"], {"source_truncated": 2})
        # 唯一的作答是一条命中；负样本一条都没答，FP 分母为 0 -> 不编 0.000
        first = rep["per_repeat"]["r1"]
        self.assertEqual(first["locate_rate"]["value"], 1.0)
        self.assertIsNone(first["false_positive_rate"]["value"])
        self.assertEqual(rep["adaptation_verdict"], "ok")

    def test_caveat_names_the_silent_count(self):
        rep = score.build_report(self.answers_dir, self.truth_dir)
        joined = "\n".join(rep["caveats"])
        self.assertIn("给不出结论", joined)
        self.assertIn("主分母是它真正作答的 1 条", joined)
        self.assertIn("source_truncated", joined)

    def test_summary_shows_both_denominators(self):
        text = score.format_summary(
            score.build_report(self.answers_dir, self.truth_dir))
        self.assertIn("作答率", text)
        self.assertIn("没答", text)
        self.assertIn("主口径只统计工具真正作答的样本", text)
        self.assertIn("受限视角", text)

    def test_no_new_fields_scores_identically(self):
        """不带 no_answer / limits 的答卷，数字与 v1.1 一模一样（v1.2 的兼容性承诺）。"""
        for path in self.answers_dir.glob("*.json"):
            path.unlink()
        payloads = {
            "s_0001": answer(find(343, 345)),
            "s_0002": answer(found=False),
            "s_0003": answer(found=False),
        }
        for sid, ans in payloads.items():
            (self.answers_dir / f"{sid}.json").write_text(
                json.dumps(ans, ensure_ascii=False), encoding="utf-8")

        rep = score.build_report(self.answers_dir, self.truth_dir)
        first = rep["per_repeat"]["r1"]
        self.assertEqual(rep["n_no_answer"], 0)
        self.assertEqual(rep["coverage_limits"], {})
        self.assertNotIn("no_answer", first["n"])      # 没答案就没这一格
        self.assertEqual(first["locate_rate"]["value"], 0.5)
        self.assertEqual(first["false_positive_rate"]["value"], 0.0)
        self.assertEqual(first["n"]["positives"], 2)
        self.assertEqual(first["n"]["negatives"], 1)
        # 主口径与老口径重合 —— 没有沉默可剔
        self.assertEqual(first["silence_as_no_finding"]["locate_rate"]["value"],
                         first["locate_rate"]["value"])
        joined = "\n".join(rep["caveats"])
        self.assertNotIn("给不出结论", joined)


class TestNoAnswerValidation(unittest.TestCase):
    """两个可选字段的类型必须硬：宁可判 invalid_output，也不要静默当成没写。"""

    def test_no_answer_accepts_a_bucket_name(self):
        self.assertEqual(score.validate_answer(
            answer(found=False, no_answer="source_truncated")), [])

    def test_no_answer_rejects_empty_and_non_string(self):
        self.assertTrue(score.validate_answer(answer(found=False, no_answer="  ")))
        self.assertTrue(score.validate_answer(answer(found=False, no_answer=123)))

    def test_no_answer_conflicting_with_found_true_is_rejected(self):
        self.assertTrue(score.validate_answer(
            answer(find(343, 345), no_answer="source_truncated")))

    def test_limits_accepts_string_list(self):
        self.assertEqual(score.validate_answer(
            answer(found=False, limits=["source_truncated"])), [])

    def test_limits_rejects_non_list_and_empty_items(self):
        self.assertTrue(score.validate_answer(answer(found=False, limits="x")))
        self.assertTrue(score.validate_answer(answer(found=False, limits=[""])))
        self.assertTrue(score.validate_answer(answer(found=False, limits=[1])))


CODE = "\n".join([
    "public class C {",                              # 1
    "    void doStart() {",                          # 2
    "        Object x = context.lookup(name);",      # 3
    "        return;",                               # 4
    "    }",                                         # 5
    "    void other() {",                            # 6
    "        Object y = context.lookup(other);",     # 7
    "    }",                                         # 8
    "}",                                             # 9
    "",
])


class TestLocatorFidelity(unittest.TestCase):
    """X17：工具自己抄的代码片段，和它自己报的行号对不上 —— 判分本身看不出来这件事。

    纯判分里，一个"诚实地没找到"和一个"报了但位置是错的"在正样本上都显示 miss；
    差别只在这条 finding 的 evidence 到底落在源码第几行。
    """

    def status(self, body_lines, reported, code=CODE):
        evidence = "repo/C.java:%s\n%s" % (reported, "\n".join(body_lines))
        return score.locator_status(evidence, code, reported)

    def test_snippet_at_reported_line_is_ok(self):
        self.assertEqual(
            self.status(["Object x = context.lookup(name);"], 3), "content_ok")

    def test_snippet_far_from_reported_line_is_far(self):
        # 工具报第 3 行，片段其实在第 7 行
        self.assertEqual(
            self.status(["Object y = context.lookup(other);"], 3), "content_far")

    def test_tolerance_is_three_lines(self):
        self.assertEqual(
            self.status(["Object x = context.lookup(name);"], 6), "content_ok")
        self.assertEqual(
            self.status(["Object x = context.lookup(name);"], 7), "content_far")

    def test_unmatched_snippet_is_not_found(self):
        self.assertEqual(
            self.status(["something that is not in the file"], 3), "content_not_found")

    def test_short_lines_do_not_count_as_matches(self):
        # `}` / `return;` 这种短行在任何文件里都能撞上，不能拿来当证据
        self.assertEqual(self.status(["    }"], 3), "content_not_found")

    def test_evidence_without_code_is_na(self):
        # 只有 `path:line` 一行，没有可核对的片段
        self.assertEqual(score.locator_status("repo/C.java:3", CODE, 3), "content_na")

    def test_missing_source_is_na(self):
        self.assertEqual(
            score.locator_status("repo/C.java:3\nObject x = context.lookup(name);",
                                 "", 3), "content_na")

    def test_json_evidence_is_na(self):
        # JSON 形态的 evidence 里没有片段可核 —— 判"无法判断"，不是"对不上"
        self.assertEqual(
            score.locator_status('{"finding": {"line": 3}}', CODE, 3), "content_na")


class TestLocatorInReport(unittest.TestCase):
    """保真度进报表：只在给了源码时跑，而且**不改任何一个分数**。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.truth_dir = root / "truth"
        self.answers_dir = root / "answers"
        self.truth_dir.mkdir()
        self.answers_dir.mkdir()
        good = find(3, 3)
        good["evidence"] = "repo/C.java:3\nObject x = context.lookup(name);"
        far = find(3, 3)
        far["evidence"] = "repo/C.java:3\nObject y = context.lookup(other);"
        samples = {
            "s_0001": (truth("pre", "s_0001"), answer(good)),        # strict_hit，对得上
            "s_0002": (truth("pre", "s_0002"), answer(found=False)),  # miss，无片段
            "s_0003": (truth("post", "s_0003"), answer(far)),        # FP，对不上
        }
        for sid, (meta, ans) in samples.items():
            (self.truth_dir / f"{sid}.json").write_text(
                json.dumps(meta, ensure_ascii=False), encoding="utf-8")
            (self.answers_dir / f"{sid}.json").write_text(
                json.dumps(ans, ensure_ascii=False), encoding="utf-8")
        self.code_table = {"s_0001": CODE, "s_0002": CODE, "s_0003": CODE}

    def tearDown(self):
        self.tmp.cleanup()

    def test_counts_per_finding(self):
        rep = score.build_report(self.answers_dir, self.truth_dir, self.code_table)
        fid = rep["locator_fidelity"]
        self.assertEqual(fid["checked"], 2)      # s_0002 没有 finding，不算
        self.assertEqual(fid["content_ok"], 1)
        self.assertEqual(fid["content_far"], 1)
        self.assertEqual(fid["content_not_found"], 0)

    def test_caveat_calls_out_the_far_count(self):
        rep = score.build_report(self.answers_dir, self.truth_dir, self.code_table)
        joined = "\n".join(rep["caveats"])
        self.assertIn("对不上", joined)
        self.assertIn("定位不可信", joined)

    def test_scores_are_untouched(self):
        without = score.build_report(self.answers_dir, self.truth_dir)
        with_code = score.build_report(self.answers_dir, self.truth_dir, self.code_table)
        for key in ("locate_rate", "strict_locate_rate",
                    "false_positive_rate", "balanced_accuracy"):
            self.assertEqual(without["per_repeat"]["r1"][key],
                             with_code["per_repeat"]["r1"][key], key)
        # 不给源码时这一项不跑：checked=0，也不该冒出"对不上"的 caveat
        self.assertEqual(without["locator_fidelity"]["checked"], 0)
        self.assertNotIn("定位不可信", "\n".join(without["caveats"]))

    def test_summary_shows_fidelity_line(self):
        text = score.format_summary(
            score.build_report(self.answers_dir, self.truth_dir, self.code_table))
        self.assertIn("位置保真", text)


class TestLocatorParity(unittest.TestCase):
    """报表里的核对与 `deploy/eval/verify_answers.py` 必须同一套算法。

    两份实现分别在"判分"和"离线复查"两条路上跑，对同一批输入给出不同答案的话，
    报表与 D5 自查会互相打架 —— 而它们本来是用来互相印证的。
    """

    CASES = [
        ("repo/C.java:3\nObject x = context.lookup(name);", 3),
        ("repo/C.java:3\nObject y = context.lookup(other);", 3),
        ("repo/C.java:3\nsomething that is not in the file", 3),
        ("repo/C.java:3\n    }", 3),
        ("repo/C.java:3\njust a message", 3),
        ('{"finding": {"line": 3}}', 3),
        ("", 3),
    ]

    def setUp(self):
        path = Path(__file__).resolve().parents[7] / "deploy" / "eval" / "verify_answers.py"
        if not path.is_file():
            self.skipTest(f"没有离线复查脚本: {path}")
        import importlib.util
        spec = importlib.util.spec_from_file_location("_verify_answers", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)      # type: ignore[union-attr]
        self.verify = module

    def test_same_bucket_for_the_same_input(self):
        for evidence, reported in self.CASES:
            mine = score.locator_status(evidence, CODE, reported)
            theirs = self.verify._content_check(
                self.verify._evidence_body_lines(evidence), CODE, reported)[0]
            self.assertEqual(mine, theirs, evidence)


if __name__ == "__main__":
    unittest.main(verbosity=2)
