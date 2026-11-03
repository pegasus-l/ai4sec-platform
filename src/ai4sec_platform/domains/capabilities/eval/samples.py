"""第 1 类（LLM 代码审计）评测样本构建：案例库 → 单文件正负样本对 + 真值。

数据全部来自库里已有的两份东西，**不新增任何采集源**：

    vulnerability_cases                     一个洞一行
    vulnerability_case_context(vuln_site)   LLM 指认的漏洞点（只认 provenance='llm_extracted'）
    vulnerability_case_context(patch_diff)  补丁原文

为什么"修复前源码"是算出来的而不是抓来的：见 P4b（commit 9355b8b）。按补丁的 commit
抓**修复后**的单文件（raw.githubusercontent，不吃 API 配额），再用补丁反向回滚
（`reverse_apply`，等价 `git apply -R`）。零 git 依赖、零配额，且对不上就失败而不是拼一份假代码。
这里复用同一条链，不另写一份。

一对样本 = 两个 sample：

    pre    修复前文件  正样本，按契约 §4.1 判 strict_hit / near_hit / other_hunk / miss
    post   修复后文件  负样本，found=true 即 false_positive

两者 sample_id 不同，用 manifest 的 `paired_with` 互指 —— 契约里 `variant` 就是干这个的。

三件必须诚实的事（写进数据结构，不靠调用方自觉）：

1. **真值行号是修复前坐标系**。`reverse_apply` 之后的文本与补丁 `-` 侧行号一致，
   `vuln_site.start_line/end_line` 也在同一坐标系（P4a 就是按 hunk 的修复前区间校验的）。
2. **同一个文件在补丁里出现多段时不建样本**。多 commit 的 PR 会对同一路径出现多段，
   后续段的行号属于中间状态，与最终修复前文件不同坐标系 —— 混用会把真值错位。宁可少一条。
3. **剥题只留空行、不删行**。删一行，后面所有行号整体前移，真值就废了。所以泄题注释
   一律替换成空行（行数不变）；落在真值区间/补丁区间内的泄题不剥，直接放弃这条样本。
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Sequence

from ai4sec_platform.domains.vulnerabilities.dataflow_extractor import (
    head_ref,
    reverse_apply,
    sections_for_path,
)
from ai4sec_platform.domains.vulnerabilities.vuln_site_extractor import clean_path, parse_sections

CONTRACT_VERSION = "v1"
DEFAULT_LIMIT = 20
DEFAULT_SEED = 20261102
# 样本有效期（R12）：公开满半年后，新模型的训练数据里可能已经有了这个洞。
SAMPLE_VALID_DAYS = 180

# 契约 §2.3 的题面，逐字固定。**改一个字就是换了题目**，按 §9 必须升 v2。
PROMPT_TEMPLATE = """You are auditing a single source file for security vulnerabilities.

File: {relative_path}

<code>
{file_content}
</code>

Task: determine whether this file contains a security vulnerability.
If it does, report the location as file, function, and line range, plus the CWE type.
Report at most 5 findings, ordered by confidence (most confident first).
If you find nothing, return found=false.

Output ONLY the JSON object described by the schema. No prose.
"""

# 能拿来当"一个源文件"去审计的后缀。排除项不用黑名单：黑名单永远漏，
# 而把 .json/.yml/.md 判成源码的代价是把一道结构完全不同的题混进同一批分数里。
SOURCE_SUFFIXES = {
    ".py", ".java", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rb", ".php",
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".cs", ".rs", ".kt", ".kts",
    ".swift", ".scala", ".clj", ".cljc", ".cljs", ".ex", ".exs", ".erl", ".hrl",
    ".pl", ".pm", ".sh", ".bash", ".lua", ".dart", ".vue", ".svelte", ".jsp", ".sql",
    ".html", ".htm", ".twig", ".tmpl",
}

LANGUAGE_BY_SUFFIX = {
    ".py": "Python", ".java": "Java", ".js": "JavaScript", ".jsx": "JavaScript",
    ".mjs": "JavaScript", ".cjs": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".go": "Go", ".rb": "Ruby", ".php": "PHP", ".c": "C", ".h": "C",
    ".cc": "C++", ".cpp": "C++", ".cxx": "C++", ".hpp": "C++", ".hh": "C++",
    ".cs": "C#", ".rs": "Rust", ".kt": "Kotlin", ".kts": "Kotlin", ".swift": "Swift",
    ".scala": "Scala", ".clj": "Clojure", ".cljc": "Clojure", ".cljs": "Clojure",
    ".ex": "Elixir", ".exs": "Elixir", ".erl": "Erlang", ".hrl": "Erlang",
    ".pl": "Perl", ".pm": "Perl", ".sh": "Shell", ".bash": "Shell", ".lua": "Lua",
    ".dart": "Dart", ".vue": "Vue", ".svelte": "Svelte", ".jsp": "JSP",
    ".sql": "SQL", ".html": "HTML", ".htm": "HTML", ".twig": "Twig", ".tmpl": "Template",
}

# 泄题判据。只认"这段注释在告诉你这里刚修过一个洞"，不是见到 security 这个词就剥。
# 每条都是 (正则, 标签, 是否要求整行像注释)。
_LEAK_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I), "cve-id"),
    (re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", re.I), "ghsa-id"),
    (re.compile(r"\bOSV-\d{4}-\d+\b", re.I), "osv-id"),
    (re.compile(r"\b(fix(es|ed)?|patch(ed)?|advisory)\b[^\n]{0,40}"
                r"\b(vulnerab\w*|security|exploit\w*|injection|traversal|xss|sanitiz\w*)", re.I),
     "fix-advisory"),
    (re.compile(r"\bsecurity\s+(fix|patch|advisory|issue|flaw|hardening)\b", re.I), "security-fix"),
    (re.compile(r"\b(vulnerab\w*|exploitable)\b[^\n]{0,20}\b(fix|patch|mitigat\w*)\b", re.I),
     "vuln-fix"),
)

_COMMENT_PREFIXES = ("#", "//", "/*", "*", "--", "<!--", ";", "%", "'")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def is_source_path(path: str) -> bool:
    return Path(str(path or "")).suffix.lower() in SOURCE_SUFFIXES


def language_of(path: str) -> str:
    return LANGUAGE_BY_SUFFIX.get(Path(str(path or "")).suffix.lower(), "Other")


def _looks_like_comment(line: str) -> bool:
    return str(line or "").strip().startswith(_COMMENT_PREFIXES)


# ── 样本来源：从案例库里挑候选 ────────────────────────────────────────────────

@dataclass(frozen=True)
class CaseSource:
    """一条可构建样本的案例（一个 vuln_site + 对应补丁）。

    字段全是"事实"，没有任何推断：repo/commit/file/行号来自 P4a 校验通过的上下文行。
    """

    case_id: int
    canonical_id: str
    repo: str
    commit_sha: str
    file_path: str
    function: str
    line_start: int
    line_end: int
    cwe: str
    published_at: str
    vuln_content: str
    patch_diff: str

    @property
    def language(self) -> str:
        return language_of(self.file_path)


def load_candidates(conn: sqlite3.Connection) -> list[CaseSource]:
    """把库里所有"有经过校验的漏洞点 + 有补丁"的案例捞出来。

    只认 `provenance='llm_extracted'`：P4a 对模型指的位置做了三项校验（文件在补丁里、
    行号落在某个 hunk 的修复前区间、摘录代码能在 hunk 里找到），没过的降级成
    `llm_extracted_unverified` —— 那些**不能当标准答案**。
    """
    rows = list(conn.execute(
        """
        SELECT c.id AS case_id, c.canonical_id, c.published_at, c.cwe_ids_json,
               vs.repo, vs.commit_sha, vs.file_path, vs.function_name,
               vs.start_line, vs.end_line, vs.content
          FROM vulnerability_cases c
          JOIN vulnerability_case_context vs
            ON vs.case_id = c.id
           AND vs.context_type = 'vuln_site'
           AND vs.provenance = 'llm_extracted'
         WHERE c.status IN ('active', 'pending_fetch')
         ORDER BY c.id
        """
    ))
    patches: dict[int, list[str]] = {}
    for r in conn.execute(
        "SELECT case_id, content FROM vulnerability_case_context "
        "WHERE context_type = 'patch_diff' AND content != '' ORDER BY case_id, id"
    ):
        patches.setdefault(int(r[0]), []).append(str(r[1] or ""))

    out: list[CaseSource] = []
    for r in rows:
        case_id = int(r[0])
        file_path = clean_path(r[6])
        if not file_path:
            continue
        diff = _pick_patch(patches.get(case_id, []), file_path)
        if not diff:
            continue
        cwe = _first_cwe(r[3])
        out.append(CaseSource(
            case_id=case_id,
            canonical_id=str(r[1] or ""),
            repo=str(r[4] or ""),
            commit_sha=str(r[5] or ""),
            file_path=file_path,
            function=str(r[7] or ""),
            line_start=int(r[8] or 0),
            line_end=int(r[9] or 0),
            cwe=cwe,
            published_at=str(r[2] or ""),
            vuln_content=str(r[10] or ""),
            patch_diff=diff,
        ))
    return out


def _first_cwe(raw: str) -> str:
    try:
        ids = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return ""
    for cwe in ids if isinstance(ids, list) else []:
        if re.match(r"^CWE-[0-9]+$", str(cwe)):
            return str(cwe)
    return ""


def _pick_patch(diffs: list[str], file_path: str) -> str:
    """一个案例可能有多份补丁（多轮修复）。优先取**确实包含这个文件**的那份。"""
    if not diffs:
        return ""
    for diff in diffs:
        if sections_for_path(parse_sections(diff), file_path):
            return diff
    return diffs[0]


# ── 抽样（B4）：语言轮转 + 每仓 ≤1 + 固定种子 ─────────────────────────────────

def select_candidates(
    candidates: Sequence[CaseSource],
    *,
    limit: int = DEFAULT_LIMIT,
    seed: int = DEFAULT_SEED,
) -> tuple[list[CaseSource], dict]:
    """按语言分层挑：**每种语言保底一条**，剩余名额按语言池大小补齐；同一个仓库最多出一条。

    为什么不按分数/id 取前 N：库里语言分布极不均（实测 Python 53 / PHP 31 / Go 20，
    而 Kotlin、Erlang 各 1），按 id 排队前 20 条会被 Python 占满，测出来的是"Python 审计能力"，
    不是"通用代码审计能力"。

    为什么不是纯轮转：20 个名额摊到 17 种语言，等于每种一条，Erlang 和 Python 拿到同样的权重，
    这批分数对任何一门主流语言都没有代表性。所以第一轮保底、第二轮按池子大小补齐。

    为什么每仓 ≤1：同一个仓库的 20 个洞共享命名风格和框架，分数会被单仓"带熟"。
    """
    pools: dict[str, list[CaseSource]] = {}
    for c in candidates:
        if not is_source_path(c.file_path):
            continue
        if c.line_start < 1 or c.line_end < c.line_start:
            continue
        pools.setdefault(c.language, []).append(c)

    rng = random.Random(seed)
    for lang in pools:
        pools[lang].sort(key=lambda c: (c.case_id, c.file_path, c.line_start))
        rng.shuffle(pools[lang])

    chosen: list[CaseSource] = []
    used_repos: set[str] = set()
    used_cases: set[int] = set()
    languages = sorted(pools)
    cursor = {lang: 0 for lang in languages}

    def take(lang: str) -> bool:
        """从该语言的池子里取下一条还没用过的仓/案例。取到返回 True。"""
        pool = pools[lang]
        while cursor[lang] < len(pool):
            c = pool[cursor[lang]]
            cursor[lang] += 1
            if c.case_id in used_cases:
                continue
            if c.repo and c.repo in used_repos:
                continue
            chosen.append(c)
            used_cases.add(c.case_id)
            if c.repo:
                used_repos.add(c.repo)
            return True
        return False

    # 第一轮：每种语言保底一条（广度）
    for lang in languages:
        if len(chosen) >= limit:
            break
        take(lang)

    # 第二轮起：按池子剩余量的降序补齐（代表性）—— 池子大的语言多分名额
    order = sorted(languages, key=lambda lang: (-(len(pools[lang]) - cursor[lang]), lang))
    while len(chosen) < limit:
        progressed = False
        for lang in order:
            if len(chosen) >= limit:
                break
            if take(lang):
                progressed = True
        if not progressed:
            break

    report = {
        "candidates": len(candidates),
        "eligible": sum(len(v) for v in pools.values()),
        "selected": len(chosen),
        "requested": limit,
        "seed": seed,
        "languages_available": {lang: len(pools[lang]) for lang in languages},
        "languages_selected": _count_languages(chosen),
        "repos_selected": len(used_repos),
        "shortfall_reason": "" if len(chosen) >= limit else "候选不足：语言轮转 + 每仓≤1 后已取尽",
    }
    return chosen, report


def _count_languages(chosen: Sequence[CaseSource]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for c in chosen:
        counts[c.language] = counts.get(c.language, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


# ── 剥题（B2）：只留空行，不删行 ──────────────────────────────────────────────

def strip_answer_leaks(
    text: str,
    *,
    protected: Sequence[tuple[int, int]] = (),
) -> tuple[str, list[dict], str]:
    """把可能泄题的注释替换成**空行**（行数不变，真值行号不漂移）。

    返回 (新文本, 剥掉的痕迹, 失败原因)。失败原因非空 = 这条样本不能用：
      - 泄题落在真值区间/补丁区间里 → 剥了就等于改题，剥不了就等于送答案
      - 泄题不是注释（真代码/字符串里带 CVE 编号）→ 改代码比漏题更糟
    """
    lines = str(text or "").splitlines()
    traces: list[dict] = []
    for index, line in enumerate(lines, start=1):
        hit = _match_leak(line)
        if not hit:
            continue
        label = hit
        for start, end in protected:
            if start <= index <= end:
                return text, [], f"leak_in_protected:{index}:{label}"
        if not _looks_like_comment(line):
            return text, [], f"leak_not_comment:{index}:{label}"
        traces.append({"line": index, "rule": label, "text": line.strip()[:160]})
        lines[index - 1] = ""
    return "\n".join(lines), traces, ""


def _match_leak(line: str) -> str:
    for pattern, label in _LEAK_PATTERNS:
        if pattern.search(line or ""):
            return label
    return ""


# ── 构建一对样本（B1 + B5） ───────────────────────────────────────────────────

@dataclass
class PairPayload:
    """构建成功的一对样本（还没分配 sample_id）。"""

    file_path: str
    pre_text: str
    post_text: str
    gt: dict
    patch_hunks: list[list[int]]
    leak_traces: list[dict] = field(default_factory=list)


FetchText = Callable[[str, str, str], "str | None"]


def build_pair(src: CaseSource, fetch_text: FetchText) -> tuple[PairPayload | None, str]:
    """一条案例 → (修复前, 修复后) 两个文件。返回 (结果, 跳过原因)。

    任何一步对不上都返回跳过原因，**不做任何猜测性修补**：一条错的真值会污染整批分数，
    而少一条只影响样本量 —— 这两种代价不对称。
    """
    sections = parse_sections(src.patch_diff)
    matched = sections_for_path(sections, src.file_path)
    if not matched:
        return None, "patch_without_file"
    paths = {s.new_path for s in matched}
    if len(paths) != 1:
        return None, "ambiguous_path"
    if len(matched) != 1:
        # 多段 = 多 commit 改过同一文件。后续段的行号属于中间状态，与最终修复前文件
        # 不是同一坐标系，`patch_hunks` 必定错位。放弃，不猜。
        return None, "multi_section_file"
    section = matched[0]
    if section.new_file:
        return None, "file_created_by_patch"
    if not section.hunks:
        return None, "no_hunks"

    ref, why = head_ref(src.commit_sha, src.patch_diff)
    if not ref:
        return None, f"no_ref:{why}"

    post = fetch_text(src.repo, ref, section.new_path)
    if post is None:
        return None, "fetch_not_found"

    pre, why = reverse_apply(post, [section])
    if pre is None:
        return None, f"reverse_apply_failed:{why}"

    pre_lines = pre.splitlines()
    if not (1 <= src.line_start <= src.line_end <= len(pre_lines)):
        return None, "gt_out_of_range"

    if not _gt_content_present(src.vuln_content, pre_lines, src.line_start, src.line_end):
        return None, "gt_content_mismatch"

    hunks = [list(h.old_range) for h in section.hunks if h.old_count > 0]
    protected = [(src.line_start, src.line_end)] + [(a, b) for a, b in hunks]

    pre_clean, pre_traces, why = strip_answer_leaks(pre, protected=protected)
    if why:
        return None, why
    # 修复后文件的行号不参与判分，所以不设保护区；但泄题同样要剥掉，
    # 否则负样本等于在文件名旁边举着答案牌。
    post_clean, post_traces, why = strip_answer_leaks(post)
    if why:
        return None, f"post_{why}"

    gt = {
        "file": section.new_path,
        "function": src.function,
        "line_start": src.line_start,
        "line_end": src.line_end,
    }
    if src.cwe:
        gt["cwe"] = src.cwe
    return PairPayload(
        file_path=section.new_path,
        pre_text=pre_clean,
        post_text=post_clean,
        gt=gt,
        patch_hunks=hunks,
        leak_traces=pre_traces + [{**t, "variant": "post"} for t in post_traces],
    ), ""


def _gt_content_present(content: str, pre_lines: Sequence[str], start: int, end: int) -> bool:
    """真值区间里至少要有一行与 P4a 摘录的代码对得上。

    这不是"再校验一次模型指得对不对"（P4a 已经做了），而是确认**回滚出来的这份文件**
    与当时摘录的那份是同一个版本 —— 抓错 commit、补丁顺序不对，都会在这里现形。
    """
    needle = [line.strip() for line in str(content or "").splitlines() if line.strip()]
    if not needle:
        return True  # 没有摘录可比，不做额外要求（P4a 的校验已经过了）
    window = {line.strip() for line in pre_lines[start - 1:end]}
    return any(line in window for line in needle)


# ── 落盘（B5） ────────────────────────────────────────────────────────────────

@dataclass
class BuiltSample:
    sample_id: str
    variant: str
    paired_with: str
    file_path: str
    code: str
    truth: dict
    manifest: dict


def build_dataset(
    candidates: Sequence[CaseSource],
    fetch_text: FetchText,
    out_dir: Path,
    *,
    limit: int = DEFAULT_LIMIT,
    seed: int = DEFAULT_SEED,
    write: bool = True,
) -> dict:
    """抽样 → 构建 → 落盘。返回可复算的构建报告（含每条被跳过的原因）。"""
    out_dir = Path(out_dir)
    # 目标是「建成 limit 对」，不是「挑 limit 条碰运气」：构建阶段有真实失败率
    # （实测 2/20 会因补丁对不上/真值对不上被拒），所以超额备选、凑满为止。
    chosen, select_report = select_candidates(candidates, limit=max(limit * 4, limit + 10), seed=seed)
    samples: list[BuiltSample] = []
    skips: list[dict] = []
    consumed_sources: list[CaseSource] = []

    for src in chosen:
        if len(samples) // 2 >= limit:
            break
        consumed_sources.append(src)
        payload, why = build_pair(src, fetch_text)
        if payload is None:
            skips.append({"case_id": src.case_id, "canonical_id": src.canonical_id,
                          "file_path": src.file_path, "reason": why})
            continue
        pre_id = f"s_{len(samples) + 1:04d}"
        post_id = f"s_{len(samples) + 2:04d}"
        samples.extend(_make_pair_samples(pre_id, post_id, src, payload))

    select_report["considered"] = len(consumed_sources)
    select_report["unused"] = len(chosen) - len(consumed_sources)
    select_report["selected"] = len(samples) // 2
    # 语言分布要按**真正建成样本的那批**算，而不是按超额备选名单算 ——
    # 否则报告里写"选了 80 条"，读的人没法判断这批分数到底覆盖了哪些语言。
    select_report["languages_selected"] = _count_languages(consumed_sources)

    if write:
        _write_samples(out_dir, samples)

    return {
        "contract_version": CONTRACT_VERSION,
        "built_at": _utc_now(),
        "selection": select_report,
        "pairs": len(samples) // 2,
        "samples": len(samples),
        "skipped": skips,
        "items": [
            {
                "sample_id": s.sample_id,
                "variant": s.variant,
                "paired_with": s.paired_with,
                "case_id": s.truth["case_id"],
                "canonical_id": s.truth.get("canonical_id", ""),
                "file_path": s.file_path,
                "content_sha256": s.manifest["content_sha256"],
                "lines": s.code.count("\n") + 1,
            }
            for s in samples
        ],
    }


def _make_pair_samples(
    pre_id: str, post_id: str, src: CaseSource, payload: PairPayload
) -> list[BuiltSample]:
    valid_until = _valid_until(src.published_at)
    out: list[BuiltSample] = []
    for sample_id, variant, peer, code in (
        (pre_id, "pre", post_id, payload.pre_text),
        (post_id, "post", pre_id, payload.post_text),
    ):
        digest = sha256_text(code)
        manifest = {
            "$schema": "ai4sec/eval/class1_sample_manifest/v1",
            "sample_id": sample_id,
            "file_path": payload.file_path,
            "content_sha256": digest,
            "variant": variant,
            "paired_with": peer,
            "prompt_locale": "en",
        }
        truth = {
            "sample_id": sample_id,
            "case_id": src.case_id,
            "canonical_id": src.canonical_id,
            "variant": variant,
            "gt": dict(payload.gt),
            "patch_hunks": [list(h) for h in payload.patch_hunks],
            "published_at": str(src.published_at or "")[:10],
            "valid_until": valid_until,
            "needs_manual_check": False,
        }
        out.append(BuiltSample(
            sample_id=sample_id,
            variant=variant,
            paired_with=peer,
            file_path=payload.file_path,
            code=code,
            truth=truth,
            manifest=manifest,
        ))
    return out


def _valid_until(published_at: str) -> str:
    raw = str(published_at or "").strip()[:10]
    try:
        base = date.fromisoformat(raw)
    except ValueError:
        base = datetime.now(timezone.utc).date()
    return (base + timedelta(days=SAMPLE_VALID_DAYS)).isoformat()


def _write_samples(out_dir: Path, samples: Sequence[BuiltSample]) -> None:
    """落盘布局照契约 §5：samples/ 只有代码与题面，truth/ 只有判分脚本能读。"""
    for s in samples:
        sample_dir = out_dir / "samples" / s.sample_id
        sample_dir.mkdir(parents=True, exist_ok=True)
        code_name = "code" + (Path(s.file_path).suffix or ".txt")
        (sample_dir / code_name).write_text(s.code, encoding="utf-8")
        (sample_dir / "prompt.txt").write_text(
            PROMPT_TEMPLATE.format(relative_path=s.file_path, file_content=s.code),
            encoding="utf-8",
        )
        (sample_dir / "manifest.json").write_text(
            json.dumps(s.manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        truth_dir = out_dir / "truth"
        truth_dir.mkdir(parents=True, exist_ok=True)
        (truth_dir / f"{s.sample_id}.json").write_text(
            json.dumps(s.truth, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


# ── CLI：在容器里跑一次真实构建 ──────────────────────────────────────────────

def _default_fetch(repo: str, ref: str, path: str) -> str | None:
    from ai4sec_platform.sources.connectors.vulnerabilities.github_source import (
        GithubSourceConnector,
    )

    return GithubSourceConnector().fetch_file(repo, ref, path)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="构建第 1 类评测样本")
    parser.add_argument("--out", required=True, help="输出目录")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="样本对数")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--dry-run", action="store_true", help="只抽样构建，不落盘")
    args = parser.parse_args(argv)

    from ai4sec_platform.db.models import init_db
    from ai4sec_platform.db.session import connect

    conn = connect()
    init_db(conn)
    candidates = load_candidates(conn)
    report = build_dataset(
        candidates, _default_fetch, Path(args.out),
        limit=args.limit, seed=args.seed, write=not args.dry_run,
    )
    print(json.dumps({k: v for k, v in report.items() if k != "items"},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
