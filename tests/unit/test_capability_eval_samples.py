"""第 1 类评测样本构建：回滚对不对、剥题会不会把行号挪位、抽样会不会被单仓带熟。

这些用例守的不是"构建器能跑"，而是**假设错了会静默出坏真值**的三处：
回滚后的行号坐标系、剥题的行数不变、多段补丁必须放弃。
"""
from __future__ import annotations

import hashlib
import json

from ai4sec_platform.domains.capabilities.eval import samples as S

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
PRE = "alpha\nbeta\nVULN(x)\ngamma\ndelta"


def source(**over) -> S.CaseSource:
    base = dict(
        case_id=1, canonical_id="CVE-2026-99999", repo="acme/app", commit_sha="a" * 40,
        file_path="app.py", function="handler", line_start=3, line_end=3,
        cwe="CWE-78", published_at="2026-10-20", vuln_content="VULN(x)", patch_diff=DIFF,
    )
    base.update(over)
    return S.CaseSource(**base)


def fetcher(post: str | None = POST):
    calls: list[tuple[str, str, str]] = []

    def _fetch(repo: str, ref: str, path: str) -> str | None:
        calls.append((repo, ref, path))
        return post

    _fetch.calls = calls  # type: ignore[attr-defined]
    return _fetch


class TestBuildPair:
    def test_reverse_apply_restores_pre_fix_file(self):
        payload, why = S.build_pair(source(), fetcher())
        assert why == ""
        assert payload.pre_text == PRE
        assert payload.post_text == POST

    def test_gt_line_numbers_point_at_the_vulnerable_line(self):
        payload, _ = S.build_pair(source(), fetcher())
        lines = payload.pre_text.splitlines()
        assert lines[payload.gt["line_start"] - 1] == "VULN(x)"

    def test_patch_hunks_are_pre_fix_coordinates(self):
        payload, _ = S.build_pair(source(), fetcher())
        assert payload.patch_hunks == [[1, 5]]

    def test_fetch_uses_pinned_commit(self):
        fetch = fetcher()
        S.build_pair(source(), fetch)
        assert fetch.calls == [("acme/app", "a" * 40, "app.py")]

    def test_not_found_is_a_skip_not_a_crash(self):
        payload, why = S.build_pair(source(), fetcher(None))
        assert payload is None and why == "fetch_not_found"

    def test_patch_without_the_file_is_skipped(self):
        payload, why = S.build_pair(source(file_path="other.js"), fetcher())
        assert payload is None and why == "patch_without_file"

    def test_multi_section_file_is_skipped(self):
        # 同一个文件出现两段 = 多 commit 改过。后续段的行号属于中间状态，
        # 混进 patch_hunks 会让 other_hunk 判定指向错误的位置。宁可少一条。
        doubled = DIFF + DIFF.replace("@@ -1,5 +1,6 @@", "@@ -1,5 +1,6 @@")
        payload, why = S.build_pair(source(patch_diff=doubled), fetcher())
        assert payload is None and why == "multi_section_file"

    def test_created_file_is_skipped(self):
        created = """--- /dev/null
+++ b/new.py
@@ -0,0 +1,2 @@
+one
+two
"""
        payload, why = S.build_pair(source(file_path="new.py", patch_diff=created), fetcher())
        assert payload is None and why == "file_created_by_patch"

    def test_gt_out_of_range_is_skipped(self):
        payload, why = S.build_pair(source(line_start=99, line_end=99), fetcher())
        assert payload is None and why == "gt_out_of_range"

    def test_gt_content_mismatch_is_skipped(self):
        # 摘录的代码在回滚出来的文件里找不到 = 抓错 commit 或补丁顺序不对
        payload, why = S.build_pair(source(vuln_content="NOT_IN_FILE"), fetcher())
        assert payload is None and why == "gt_content_mismatch"


class TestStripAnswerLeaks:
    def test_blanking_keeps_line_count(self):
        text = "a\n# fixes CVE-2026-12345 here\nb"
        clean, traces, why = S.strip_answer_leaks(text)
        assert why == ""
        assert clean.count("\n") == text.count("\n")
        assert clean.splitlines()[1] == ""
        assert traces[0]["rule"] == "cve-id"

    def test_leak_inside_protected_range_refuses(self):
        text = "a\n# fixes CVE-2026-12345 here\nb"
        clean, traces, why = S.strip_answer_leaks(text, protected=[(2, 2)])
        assert clean == text and traces == []
        assert why.startswith("leak_in_protected")

    def test_leak_in_code_is_refused_rather_than_rewritten(self):
        # 改真代码比漏题更糟：宁可放弃这条样本
        text = "a\nMESSAGE = 'fixes CVE-2026-12345'\nb"
        _, _, why = S.strip_answer_leaks(text)
        assert why.startswith("leak_not_comment")

    def test_plain_code_without_leak_is_untouched(self):
        text = "def f():\n    # 普通的说明注释\n    return 1"
        clean, traces, why = S.strip_answer_leaks(text)
        assert clean == text and traces == [] and why == ""

    def test_pair_builder_strips_leak_in_both_variants(self):
        # 泄题行放在补丁 hunk 之外（第 7 行）。放在 hunk 里就等于改了被修补的代码，
        # 回滚会直接对不上 —— 那是"改代码"而不是"剥题"。
        leaky_post = POST + "\n# security patch for CVE-2026-12345\nTRAILER"
        payload, why = S.build_pair(source(), fetcher(leaky_post))
        assert why == ""
        assert "CVE-" not in payload.pre_text and "CVE-" not in payload.post_text
        assert payload.pre_text.splitlines()[5] == ""   # 修复前：第 6 行
        assert payload.post_text.splitlines()[6] == ""  # 修复后：第 7 行（多了一行修复代码）


class TestSelection:
    def _pool(self):
        out = []
        langs = [(".py", "Python"), (".go", "Go"), (".java", "Java")]
        case_id = 0
        for i in range(9):
            suffix, _lang = langs[i % 3]
            case_id += 1
            out.append(source(case_id=case_id, repo=f"acme/r{i % 4}",
                              file_path=f"f{i}{suffix}", canonical_id=f"CVE-2026-{case_id}"))
        return out

    def test_one_sample_per_repo(self):
        chosen, report = S.select_candidates(self._pool(), limit=9)
        repos = [c.repo for c in chosen]
        assert len(repos) == len(set(repos))
        assert report["selected"] == 4  # 只有 4 个仓可用，其余被"每仓≤1"挡掉

    def test_language_round_robin_spreads_languages(self):
        chosen, _ = S.select_candidates(self._pool(), limit=3)
        assert {c.language for c in chosen} == {"Python", "Go", "Java"}

    def test_extra_slots_go_to_the_larger_pool(self):
        # 保底之后剩下的名额按池子大小分：1 条 Kotlin 不该和 10 条 Python 平分 6 个名额
        pool = [source(case_id=i, repo=f"acme/py{i}", file_path=f"a{i}.py") for i in range(1, 11)]
        pool += [source(case_id=99, repo="acme/kt", file_path="a.kt")]
        chosen, _ = S.select_candidates(pool, limit=6)
        langs = [c.language for c in chosen]
        assert langs.count("Kotlin") == 1
        assert langs.count("Python") == 5

    def test_same_seed_same_selection(self):
        a, _ = S.select_candidates(self._pool(), limit=3, seed=7)
        b, _ = S.select_candidates(self._pool(), limit=3, seed=7)
        assert [c.case_id for c in a] == [c.case_id for c in b]

    def test_non_source_suffix_is_excluded(self):
        pool = [source(case_id=1, repo="a/b", file_path="package.json")]
        chosen, report = S.select_candidates(pool, limit=5)
        assert chosen == [] and report["eligible"] == 0


class TestBuildDataset:
    def test_writes_contract_layout_and_is_reproducible(self, tmp_path):
        fetch = fetcher()
        first = S.build_dataset([source()], fetch, tmp_path / "run1", limit=1)
        second = S.build_dataset([source()], fetch, tmp_path / "run2", limit=1)

        assert first["pairs"] == 1 and first["samples"] == 2
        assert [i["content_sha256"] for i in first["items"]] == \
               [i["content_sha256"] for i in second["items"]]

        sample_dir = tmp_path / "run1" / "samples" / "s_0001"
        assert (sample_dir / "code.py").read_text(encoding="utf-8") == PRE
        manifest = json.loads((sample_dir / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["variant"] == "pre" and manifest["paired_with"] == "s_0002"
        assert manifest["content_sha256"] == hashlib.sha256(PRE.encode()).hexdigest()

        prompt = (sample_dir / "prompt.txt").read_text(encoding="utf-8")
        assert "File: app.py" in prompt and "VULN(x)" in prompt

        truth = json.loads((tmp_path / "run1" / "truth" / "s_0001.json").read_text(encoding="utf-8"))
        assert truth["variant"] == "pre"
        assert truth["gt"]["line_start"] == 3
        assert truth["patch_hunks"] == [[1, 5]]
        # 报表的 window 就是从这里算的；缺了它 PRD §8 的 CHECK 过不去
        assert truth["published_at"] == "2026-10-20"

    def test_samples_directory_never_contains_truth(self, tmp_path):
        # 契约 §7 第 1 条：样本目录里不得出现真值/补丁/CVE 编号/仓库名
        S.build_dataset([source()], fetcher(), tmp_path, limit=1)
        for path in (tmp_path / "samples").rglob("*"):
            if path.is_file():
                text = path.read_text(encoding="utf-8", errors="replace")
                assert "CVE-2026-99999" not in text, path
                assert "acme/app" not in text, path
                assert all(h not in text for h in ("@@ -1,5", "--- a/app.py"))

    def test_skips_are_reported_with_reason(self, tmp_path):
        report = S.build_dataset([source(file_path="other.js")], fetcher(), tmp_path, limit=1)
        assert report["pairs"] == 0
        assert report["skipped"][0]["reason"] == "patch_without_file"
