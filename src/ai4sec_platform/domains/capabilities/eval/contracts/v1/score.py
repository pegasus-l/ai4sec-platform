#!/usr/bin/env python3
"""第 1 类「LLM 代码审计 / 漏洞发现」判分脚本 —— 契约 v1

规则条文见同目录 `class1_llm_audit.md`，本文件是它的唯一执行者。

本脚本只做一件事：把「工具交上来的答卷」和「标准答案」比对，算出指标。
它**不执行工具、不调模型、不联网、不读数据库** —— 纯文件进、纯文件出。
所以它可以拿假答卷自测（见 test_score.py），不需要等评测容器。

用法
    python3 score.py --answers <answers_dir> --truth <truth_dir> --out report.json
    python3 score.py --answers <answers_dir> --truth <truth_dir>            # 打到 stdout

目录约定（契约 §5）
    answers/
      r1/s_0001.json      # 第 1 次重复；也可直接 answers/s_0001.json 表示单轮
      r2/s_0001.json
    truth/
      s_0001.json

v1 判分口径（契约 §4，改动必须升 v2）
    strict_hit     findings 行区间与真值区间有 >=1 行交集        -> 计入 locate_rate
    near_hit       同文件同函数且距真值区间 <=15 行              -> 计入 locate_rate
    other_hunk     同文件，落在补丁其他 hunk 区间内              -> 既不算命中也不算漏报
    miss           正样本上以上三类都没有
    false_positive 负样本(修复后)上 found=true（报了任何一条就算）
    true_negative  负样本上 found=false
    invalid_output 缺文件 / 不是合法 JSON / 过不了 schema
    excluded       答卷目录里的 `_excluded.json` 点名了这个样本，且给了原因
                   （工具自报「这类样本不覆盖」——语言/平台不支持）
                   -> **不进任何分母**，也不算 invalid_output
    no_answer      答卷里带 `no_answer`（可选字段，2026-11-06 增补）：工具**扫了但自报
                   「给不出结论」**——模型没答、只看到被截断的源码、静态扫描失败。
                   它不是 `false_positive`/`true_negative`（没有判断），也不是
                   `invalid_output`（答卷格式是合规的），更不是 `excluded`（不是范围声明）
                   -> 不进主分母，单列一格；报表同时给 `silence_as_no_finding`
                      （把它们按「没发现」计的旧口径）作为**下界**

    v1 增补（2026-11-06，X15）：答卷新增两个**可选**顶层字段 `no_answer`（字符串）与
    `limits`（字符串数组，记录「这份答案是在受限视角下给出的」，如 `source_truncated`）。
    不带这两个字段的答卷，判分结果与增补前逐字一致。

    v1 增补（2026-11-06，X17）：给了样本源码时，逐条 finding 核对 evidence 里的代码片段
    到底在源码第几行（`locator_fidelity`）。`content_far` = 工具自报的行号与它自己抄的
    片段对不上 —— 这种错在纯判分里看不出来（对不上真值就是 miss，和"诚实地没找到"一样），
    但它决定了这个工具的定位到底能不能用。不给源码时这一项不跑，其它数字一字不变。

    `_excluded.json` 的形状：`{"s_0001": "language_not_supported", ...}`，
    放在 `answers/r1/` 下表示只对第 1 轮生效，放在 `answers/` 下表示单轮布局。
    没有这个文件 == 一条都没排除，旧报告的数字一字不变。
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

CONTRACT_VERSION = "v1"
NEAR_HIT_WINDOW = 15          # 契约 §4.1：同函数内距真值区间 <=15 行
MAX_FINDINGS = 5              # 契约 §3.1 #2
INVALID_OUTPUT_LIMIT = 0.20   # 契约 §6：超过 20% 判「无法适配」
# 被排除样本的占比上限。排除是"这条样本不该进这份分数", 但它同样是**分母可以被工具
# 单方面缩小**的口子: 一个在硬样本上前退出 3 的工具, 可以把自己修成"只审简单样本"。
# 所以超过这个比例就不再是"部分覆盖", 而是"这份分数不能用来代表这个工具"。
EXCLUDED_LIMIT = 0.20
EXCLUDED_MANIFEST = "_excluded.json"   # 与 store.EXCLUDED_MANIFEST 同名
CWE_RE = re.compile(r"^CWE-[0-9]+$")
LOCATOR_STATUSES = ("content_ok", "content_far",
                    "content_not_found", "content_na")

# 每个结果只保留最高等级的那条 finding（契约 §4.1「取最高等级」）
_RANK = {"strict_hit": 3, "near_hit": 2, "other_hunk": 1, None: 0}

# 契约 §8：数字旁边必须带的 caveats。不允许关掉。
# 第 3 条里的样本数与时间窗**按实际这批样本生成**，不是写死的：
# 一批 2 条样本的报表上印着"只覆盖 200 个洞"，读者会以为自己看到的是那 200 条的结果。
CAVEATS = [
    "单文件任务测不出跨文件污点追踪，工具的真实能力可能更高。",
    "真实仓库有大量噪声（vendor / 测试 / 生成代码），真实误报率会高于本评测。",
    "只覆盖 200 个洞，且全在 2026-10 之后，不代表其他漏洞类型。",   # 运行时被 caveats_for() 替换
    "结论仅限于「在最小可判定任务上，能否定位到这个洞」。",
    "判据含 LLM 成分：vuln_site 是模型从补丁里指出的，规则只校验范围不校验唯一性。"
    "不得表述为「标准答案由专家标注」。",
    "样本会过期（R12）：需对照被测模型的知识截止日；未知按「可能见过」处理。",
    "具备联网能力的工具可能自行检索到该 CVE，无法排除，如观察到需单独标注。",
]


# --------------------------------------------------------------------------
# 归一化
# --------------------------------------------------------------------------

def norm_path(value: Any) -> str:
    path = str(value or "").strip().replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def norm_func(value: Any) -> str:
    name = str(value or "").strip()
    if name.endswith("()"):
        name = name[:-2]
    return name


# --------------------------------------------------------------------------
# 几何判定
# --------------------------------------------------------------------------

def overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start <= b_end and b_start <= a_end


def gap(a_start: int, a_end: int, b_start: int, b_end: int) -> int:
    """两个闭区间的行距；相交则为 0。"""
    if overlaps(a_start, a_end, b_start, b_end):
        return 0
    if a_end < b_start:
        return b_start - a_end
    return a_start - b_end


def grade_finding(finding: dict[str, Any], gt: dict[str, Any],
                  hunks: Iterable[Iterable[int]]) -> str | None:
    """给单条 finding 定级；不匹配返回 None。契约 §4.1。"""
    if norm_path(finding.get("file")) != norm_path(gt.get("file")):
        return None

    f_start, f_end = finding["line_start"], finding["line_end"]
    g_start, g_end = gt["line_start"], gt["line_end"]

    if overlaps(f_start, f_end, g_start, g_end):
        return "strict_hit"

    # 同函数 + 15 行内。真值函数为空（文件级漏洞）时不做 near_hit 判定，
    # 否则「函数名都为空」会把两条毫不相干的位置判成同一函数。
    gt_func = norm_func(gt.get("function"))
    if gt_func and norm_func(finding.get("function")) == gt_func:
        if gap(f_start, f_end, g_start, g_end) <= NEAR_HIT_WINDOW:
            return "near_hit"

    for hunk in hunks or []:
        hunk = list(hunk or [])
        if len(hunk) == 2 and overlaps(f_start, f_end, hunk[0], hunk[1]):
            return "other_hunk"

    return None


# --------------------------------------------------------------------------
# 答卷校验（与 class1_llm_audit.schema.json 一一对应）
# --------------------------------------------------------------------------

def validate_answer(payload: Any) -> list[str]:
    """返回错误列表，空表示合规。规则与 schema 文件同源，改动必须两边一起改。"""
    if not isinstance(payload, dict):
        return ["答卷不是 JSON 对象"]
    errs: list[str] = []

    extra = set(payload) - {"found", "findings", "no_answer", "limits"}
    if extra:
        errs.append(f"不允许的顶层字段: {sorted(extra)}")
    # 可选诊断字段（v1 增补）：工具自报「给不出结论」与「答案是在受限视角下给的」。
    # 它们不影响结论本身，只影响**这条结论该怎么算分**，所以校验宽松但类型必须硬。
    if "no_answer" in payload:
        reason = payload["no_answer"]
        if not isinstance(reason, str) or not reason.strip():
            errs.append("no_answer 必须是非空字符串")
        elif payload.get("found") is True:
            # 既说「找到了」又说「给不出结论」是自相矛盾：真找到就按找到算。
            errs.append("found=true 时不能同时声明 no_answer")
    if "limits" in payload:
        limits = payload["limits"]
        if not isinstance(limits, list) or any(
                not isinstance(x, str) or not x.strip() for x in limits):
            errs.append("limits 必须是非空字符串数组")
    if "found" not in payload or not isinstance(payload["found"], bool):
        errs.append("found 缺失或不是布尔值")
    findings = payload.get("findings")
    if not isinstance(findings, list):
        return errs + ["findings 缺失或不是数组"]

    # 契约 §3.1 #2：超过 5 条不是错误，按前 5 条计。截断在 judge_sample 里做，
    # 这里只校验「found 与 findings 是否自相矛盾」。
    found = payload.get("found")
    if found is False and findings:
        errs.append("found=false 时 findings 必须为空")
    elif found is True and not findings:
        errs.append("found=true 时 findings 不能为空")

    for i, item in enumerate(findings):
        if not isinstance(item, dict):
            errs.append(f"findings[{i}] 不是对象")
            continue
        bad = set(item) - {"file", "function", "line_start", "line_end",
                           "type_cwe", "evidence"}
        if bad:
            errs.append(f"findings[{i}] 含非法字段 {sorted(bad)}")
        if not isinstance(item.get("file"), str) or not item.get("file"):
            errs.append(f"findings[{i}].file 缺失或为空")
        if "function" in item and not isinstance(item["function"], str):
            errs.append(f"findings[{i}].function 不是字符串")
        for key in ("line_start", "line_end"):
            val = item.get(key)
            if not isinstance(val, int) or isinstance(val, bool) or val < 1:
                errs.append(f"findings[{i}].{key} 不是 >=1 的整数")
        if not errs and isinstance(item.get("line_start"), int) \
                and isinstance(item.get("line_end"), int) \
                and item["line_end"] < item["line_start"]:
            errs.append(f"findings[{i}].line_end < line_start")
        cwe = item.get("type_cwe")
        if cwe is not None and not (isinstance(cwe, str) and CWE_RE.match(cwe)):
            errs.append(f"findings[{i}].type_cwe 不符合 CWE-N")
        if "evidence" in item and not isinstance(item["evidence"], str):
            errs.append(f"findings[{i}].evidence 不是字符串")
    return errs


# --------------------------------------------------------------------------
# 判分
# --------------------------------------------------------------------------

@dataclass
class Row:
    sample_id: str
    variant: str
    label: str
    detail: str = ""
    # 答案是在什么受限条件下给出的（`source_truncated` 等）。它**不改变判分**，
    # 只用来回答「这个工具在完整视角下会不会不同」—— 没有它，覆盖率无从谈起。
    limits: tuple[str, ...] = ()
    # 每条 finding 的「位置保真度」（X17）：evidence 里的代码片段是否真在答卷写的行号附近。
    # 同样**不改变判分**，它回答的是另一个问题：这个工具的定位本身可不可信。
    locator: tuple[str, ...] = ()


def judge_sample(answer: Any, truth: dict[str, Any],
                 code_text: str | None = None) -> Row:
    sample_id = truth.get("sample_id", "?")
    variant = truth.get("variant", "pre")

    errs = validate_answer(answer)
    if errs:
        return Row(sample_id, variant, "invalid_output", "; ".join(errs[:3]))

    limits = tuple(sorted({str(x).strip() for x in (answer.get("limits") or [])}))
    no_answer = answer.get("no_answer")
    if isinstance(no_answer, str) and no_answer.strip():
        # 工具扫了、也交了合规答卷，但它自己说「给不出结论」。这句话必须原样保住：
        # 以前 shim 把它翻译成 `{"found": false}`，于是"没答"在报表上变成了"没发现"。
        return Row(sample_id, variant, "no_answer", no_answer.strip()[:120], limits)

    raw = answer.get("findings") or []
    found = bool(answer.get("found"))
    findings = raw[:MAX_FINDINGS]
    locator = _locator_statuses(findings, code_text)
    truncated = f"（原有 {len(raw)} 条，按契约 §3.1 #2 截断到 {MAX_FINDINGS} 条）" \
        if len(raw) > MAX_FINDINGS else ""

    if variant == "post":
        return Row(sample_id, variant,
                   "false_positive" if found else "true_negative",
                   f"负样本报出 {len(findings)} 条{truncated}" if found else "",
                   limits, locator)

    if not found or not findings:
        return Row(sample_id, variant, "miss", "正样本未报出", limits, locator)

    gt = truth["gt"]
    hunks = truth.get("patch_hunks") or []
    best, best_rank = "miss", 0
    for finding in findings:
        label = grade_finding(finding, gt, hunks)
        rank = _RANK.get(label, 0)
        if rank > best_rank:
            best, best_rank = label or "miss", rank
    return Row(sample_id, variant, best, truncated, limits, locator)


# --------------------------------------------------------------------------
# 位置保真度（X17）：evidence 里的代码片段到底在源码第几行
# --------------------------------------------------------------------------
# 与 `deploy/eval/verify_answers.py` 是**同一套算法**（那边是离线复查工具，这边进报表）。
# 两份实现必须一致，单测 `TestLocatorParity` 拿同一批样本对拍。

LOCATOR_TOLERANCE = 3          # 片段落在答卷行号 ±3 行内即算对得上


def _squash(text: str) -> str:
    return " ".join(str(text or "").split())


def _evidence_body_lines(text: str) -> list[str]:
    """evidence 去掉首行 `{path}:{line}` 前缀（或整段 JSON）之后剩下的行。"""
    raw = str(text or "").strip()
    if not raw:
        return []
    lines = raw.split("\n")
    head = lines[0].strip()
    if head.startswith("{"):
        return []          # JSON 形态里没有代码片段可核
    if ":" in head:
        _path, _, tail = head.rpartition(":")
        if tail.strip().isdigit():
            lines = lines[1:]
    return [line for line in lines if line.strip()]


def locator_status(evidence: Any, code_text: str | None,
                   reported: Any, tol: int = LOCATOR_TOLERANCE) -> str:
    """把 evidence 里的代码片段回源码里找，返回 content_* 四种之一。

    只认「整行归一空白后完全相同」的行：散文行、模型改写过一两个字符的行都匹配不上，
    宁可判 `content_not_found`（无法判断），也不能因为模糊匹配把行号说成对的。
    """
    if not code_text:
        return "content_na"
    body = _evidence_body_lines(evidence)
    if not body:
        # evidence 只有一句消息 / 一段 JSON，没有可核对的代码 —— 无法判断，不是"对不上"
        return "content_na"
    index: dict[str, list[int]] = {}
    for number, line in enumerate(code_text.splitlines(), 1):
        index.setdefault(_squash(line), []).append(number)
    hits: list[int] = []
    for line in body:
        squashed = _squash(line)
        if len(squashed) < 8:      # 太短的行（`}`、`"""`）在任何文件里都能撞上
            continue
        hits.extend(index.get(squashed) or [])
    if not hits:
        return "content_not_found"
    low, high = min(hits), max(hits)
    if isinstance(reported, int) and not isinstance(reported, bool) \
            and low - tol <= reported <= high + tol:
        return "content_ok"
    return "content_far"


def _locator_statuses(findings: list[dict[str, Any]],
                      code_text: str | None) -> tuple[str, ...]:
    """一条答卷里每条 finding 的保真度。没给源码时整项不跑（空元组）。"""
    if code_text is None:
        return ()
    return tuple(locator_status(f.get("evidence"), code_text, f.get("line_start"))
                 for f in findings)


def _locator_counts(rows: list["Row"]) -> dict[str, int]:
    out = {k: 0 for k in LOCATOR_STATUSES}
    for row in rows:
        for status in row.locator:
            out[status] = out.get(status, 0) + 1
    return out


def wilson(hits: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    """95% Wilson 区间。total=0 返回 None（不编数字）。"""
    if total <= 0:
        return None
    p = hits / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def _ratio(hits: int, total: int) -> float | None:
    return round(hits / total, 4) if total else None


def _fmt_value(value: Any) -> str:
    """报表里的数字。None 一律印成「无」，不印 0.000 —— 分母为 0 时的 0 是编的。"""
    return "无" if value is None else f"{value:.3f}"


def tally(rows: list[Row]) -> dict[str, int]:
    keys = ["strict_hit", "near_hit", "other_hunk", "miss",
            "false_positive", "true_negative", "invalid_output", "no_answer"]
    counts = {k: 0 for k in keys}
    for row in rows:
        counts[row.label] = counts.get(row.label, 0) + 1
    return counts


def metrics(rows: list[Row]) -> dict[str, Any]:
    counts = tally(rows)
    # 被排除的样本对这份分数不提供任何信息: 它们既不是命中也不是漏报, 更不是"输出不合规"。
    # 数字照报(在 `excluded` 与 `labels` 里), 但不进任何分母。
    scorable = [r for r in rows if r.label != "excluded"]
    n_excluded = len(rows) - len(scorable)
    # `no_answer` 与 `invalid_output` 一样不进主分母：工具明说"我没给结论"，
    # 把它当成漏报就是把"沉默"记成"看过了没有"。
    answered = [r for r in scorable if r.label not in ("invalid_output", "no_answer")]
    positives = [r for r in answered if r.variant == "pre"]
    negatives = [r for r in answered if r.variant == "post"]

    strict = counts["strict_hit"]
    near = counts["near_hit"]
    fp = counts["false_positive"]
    tn = counts["true_negative"]

    locate_num = strict + near
    locate = _ratio(locate_num, len(positives))
    strict_rate = _ratio(strict, len(positives))
    fp_rate = _ratio(fp, len(negatives))
    bal = (None if locate is None or fp_rate is None
           else round((locate + (1 - fp_rate)) / 2, 4))

    # `total` 是**进分母的**样本数。没有排除时它等于原来那个 len(rows), 报表一字不变;
    # 有排除时才多出 `excluded` / `rows` 两个键, 免得"样本数"少了一截却看不出来。
    n_counts: dict[str, Any] = {"positives": len(positives), "negatives": len(negatives),
                                "total": len(scorable)}
    if n_excluded:
        n_counts["excluded"] = n_excluded
        n_counts["rows"] = len(rows)
    # 作答率是这份报表里最容易被跳过、又最该先看的一个数：一个只在 15/40 上开口的
    # 工具，另外 25 条上的"成绩"本来就不存在。
    n_counts["answered"] = len(answered)
    if counts["no_answer"]:
        n_counts["no_answer"] = counts["no_answer"]
        n_counts["rows"] = len(rows)

    # 旧口径（沉默按"没发现"计）—— 保留它是为了给出**下界**，而不是继续当主口径。
    # 正样本沉默 = 漏报，负样本沉默 = 放过，这两句只有在工具声明"我给不出结论"时
    # 才有意义：它确实没判断，所以这条下界既不是冤枉也不是洗白，是"最坏读法"。
    legacy_pos = [r for r in scorable if r.variant == "pre" and r.label != "invalid_output"]
    legacy_neg = [r for r in scorable if r.variant == "post" and r.label != "invalid_output"]
    legacy_locate = _ratio(locate_num, len(legacy_pos))
    legacy_fp = _ratio(fp, len(legacy_neg))
    legacy_bal = (None if legacy_locate is None or legacy_fp is None
                  else round((legacy_locate + (1 - legacy_fp)) / 2, 4))
    locator = _locator_counts(rows)
    return {
        "labels": counts,
        "n": n_counts,
        "locate_rate": {
            "value": locate, "k": locate_num, "n": len(positives),
            "ci95": wilson(locate_num, len(positives)),
        },
        "strict_locate_rate": {
            "value": strict_rate, "k": strict, "n": len(positives),
            "ci95": wilson(strict, len(positives)),
        },
        "false_positive_rate": {
            "value": fp_rate, "k": fp, "n": len(negatives),
            "ci95": wilson(fp, len(negatives)),
        },
        "balanced_accuracy": {
            "value": bal,
            "note": "(locate_rate + (1 - false_positive_rate)) / 2",
        },
        "invalid_output": {
            "rate": _ratio(counts["invalid_output"], len(scorable)),
            "k": counts["invalid_output"], "n": len(scorable),
            "threshold": INVALID_OUTPUT_LIMIT,
        },
        "excluded": {
            "rate": _ratio(n_excluded, len(rows)),
            "k": n_excluded, "n": len(rows),
            "threshold": EXCLUDED_LIMIT,
            "reasons": _reason_counts(rows),
        },
        "no_answer": {
            "rate": _ratio(counts["no_answer"], len(scorable)),
            "k": counts["no_answer"], "n": len(scorable),
            "reasons": _reason_counts(rows, "no_answer"),
            "note": "工具自报给不出结论，不进主分母；它既不是漏报也不是「没发现」",
        },
        "coverage": {
            "rows": len(rows),
            "answered": len(answered),
            "answered_rate": _ratio(len(answered), len(rows)),
            "no_answer": counts["no_answer"],
            "invalid_output": counts["invalid_output"],
            "excluded": n_excluded,
        },
        "limits": _limit_counts(rows),
        # X17：工具自报的行号与它自己抄的代码片段对不上 —— 这是"定位不可信"，不是"没找到"。
        # 分母是**逐条 finding**，不是样本：一份答卷可以报 3 条，其中 1 条对不上。
        "locator_fidelity": {
            **locator,
            "checked": sum(locator.values()),
            "note": ("逐条 finding 核对 evidence 里的代码片段是否真在答卷写的行号附近；"
                     "content_far = 工具自己报错了行号"),
        },
        "silence_as_no_finding": {
            "note": "旧口径/下界：把 no_answer 当「没发现」算。主口径已剔除这些样本",
            "locate_rate": {"value": legacy_locate, "k": locate_num, "n": len(legacy_pos),
                            "ci95": wilson(locate_num, len(legacy_pos))},
            "false_positive_rate": {"value": legacy_fp, "k": fp, "n": len(legacy_neg),
                                    "ci95": wilson(fp, len(legacy_neg))},
            "balanced_accuracy": {"value": legacy_bal},
        },
    }


def _reason_counts(rows: list[Row], label: str = "excluded") -> dict[str, int]:
    """排除/没答原因分组。报表要能回答"这些是哪一类", 不然一个总数就是在让人猜。

    `no_answer` 的理由来自工具自报（`source_truncated` / `logic_review_inconclusive` …），
    按原样分桶：换一个工具、换一个理由，报表不用改代码就能显示出来。
    """
    out: dict[str, int] = {}
    for row in rows:
        if row.label == label:
            key = row.detail or "未注明原因"
            out[key] = out.get(key, 0) + 1
    return out


def _limit_counts(rows: list[Row]) -> dict[str, int]:
    """答案是在什么受限视角下给出的。**不改变任何分数**，只回答覆盖面的边界。

    例如 `source_truncated: 25` 意思是「25 份答案只看到了文件的前 N 个字符」——
    这些样本的 locate 率再高，也不能说成"它能审这个仓库"。
    """
    out: dict[str, int] = {}
    for row in rows:
        for limit in row.limits:
            out[limit] = out.get(limit, 0) + 1
    return out


def _pick(m: dict[str, Any], path: tuple[str, ...]) -> Any:
    node: Any = m
    for key in path:
        node = node[key]
    return node


def aggregate(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """跨重复聚合：中位数 + 极值 + 是否完全一致 + 中位那一轮的区间。"""
    names = [
        ("locate_rate", ("locate_rate", "value"), ("locate_rate", "ci95")),
        ("strict_locate_rate", ("strict_locate_rate", "value"),
         ("strict_locate_rate", "ci95")),
        ("false_positive_rate", ("false_positive_rate", "value"),
         ("false_positive_rate", "ci95")),
        ("balanced_accuracy", ("balanced_accuracy", "value"), None),
        # 作答率与被剔除的"没答"样本：主口径的分母就是它们变出来的，必须一起看。
        ("answered_rate", ("coverage", "answered_rate"), None),
        ("no_answer_rate", ("no_answer", "rate"), None),
        ("locate_rate_silence_as_no_finding",
         ("silence_as_no_finding", "locate_rate", "value"),
         ("silence_as_no_finding", "locate_rate", "ci95")),
    ]
    out: dict[str, Any] = {}
    for label, path, ci_path in names:
        values = [_pick(r, path) for r in reports]
        defined = [v for v in values if v is not None]
        if not defined:
            out[label] = {"median": None, "values": values,
                          "note": "全部重复都无有效分母"}
            continue
        ordered = sorted(defined)
        mid = len(ordered) // 2
        median = (ordered[mid] if len(ordered) % 2
                  else round((ordered[mid - 1] + ordered[mid]) / 2, 4))
        # 取与中位数最接近的那一轮，把它的区间作为中位的区间
        closest_i = min(range(len(values)),
                        key=lambda i: abs((values[i] if values[i] is not None
                                           else 0) - median))
        entry = {
            "median": round(median, 4),
            "values": values,
            "min": ordered[0],
            "max": ordered[-1],
            "identical": len(set(defined)) == 1,
        }
        if ci_path:
            entry["ci95_of_median_repeat"] = _pick(reports[closest_i], ci_path)
        out[label] = entry
    return out


# --------------------------------------------------------------------------
# 载入
# --------------------------------------------------------------------------

def _load_json(path: Path) -> tuple[Any, str | None]:
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh), None
    except FileNotFoundError:
        return None, "答卷文件缺失"
    except json.JSONDecodeError as exc:
        return None, f"不是合法 JSON: {exc.msg}"
    except OSError as exc:
        return None, f"读取失败: {exc}"


def load_truth(truth_dir: Path) -> dict[str, dict[str, Any]]:
    truth: dict[str, dict[str, Any]] = {}
    for path in sorted(truth_dir.glob("*.json")):
        payload, err = _load_json(path)
        if err:
            raise SystemExit(f"真值文件不可读 {path.name}: {err}")
        if not isinstance(payload, dict) or "gt" not in payload:
            raise SystemExit(f"真值文件格式不对 {path.name}")
        if payload.get("variant") not in ("pre", "post"):
            raise SystemExit(f"真值缺 variant 字段 {path.name}")
        truth[path.stem] = payload
    if not truth:
        raise SystemExit(f"真值目录为空: {truth_dir}")
    return truth


def load_code_dir(directory: Path) -> dict[str, str]:
    """`{sample_id: 源码文本}`。支持 `<dir>/s_0001/code.py` 与 `<dir>/samples/s_0001/code.py`。

    读不到就返回空表（那一项全部判 content_na），**不猜**：拿不到源码就说拿不到。
    """
    table: dict[str, str] = {}
    if not directory or not directory.is_dir():
        return table
    nested = directory / "samples"
    root = nested if nested.is_dir() else directory
    for sample_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for entry in sorted(sample_dir.iterdir()):
            if entry.name.startswith("code") and "." in entry.name and entry.is_file():
                try:
                    table[sample_dir.name] = entry.read_text(encoding="utf-8",
                                                            errors="replace")
                except OSError:
                    pass
                break
    return table


def _answer_files(directory: Path) -> dict[str, Path]:
    """目录里的答卷。`_` 开头的是**清单**(如 `_excluded.json`), 不是答卷。"""
    return {p.stem: p for p in directory.glob("*.json") if not p.name.startswith("_")}


def discover_repeats(answers_dir: Path) -> dict[str, dict[str, Path]]:
    """返回 {repeat_name: {sample_id: path}}。支持扁平与 r1/r2/r3 两种布局。

    只带 `_excluded.json`、一份答卷都没有的轮次**也算一轮**: 全部样本都被排除是一个合法
    且必须如实报出来的结果(分母为 0), 不是"这一轮没跑"。
    """
    repeats: dict[str, dict[str, Path]] = {}
    flat = _answer_files(answers_dir)
    if flat or (answers_dir / EXCLUDED_MANIFEST).is_file():
        repeats["r1"] = flat
    for sub in sorted(p for p in answers_dir.iterdir() if p.is_dir()):
        found = _answer_files(sub)
        if found or (sub / EXCLUDED_MANIFEST).is_file():
            repeats[sub.name] = found
    if not repeats:
        raise SystemExit(f"答卷目录里没有任何 .json: {answers_dir}")
    return repeats


def _repeat_dir(answers_dir: Path, name: str) -> Path:
    """这一轮的目录。扁平布局下 repeat 的目录就是 answers_dir 本身。"""
    sub = answers_dir / name
    return sub if sub.is_dir() else answers_dir


def load_excluded(directory: Path) -> dict[str, str]:
    """读 `_excluded.json`: {sample_id: 原因}。没有这个文件 = 一条都没排除。

    文件在但读不懂时**直接失败**, 不退回"当作没排除": 那样这些样本会被记成
    `invalid_output`, 于是"语言不支持"重新变成"工具输出不合规" —— 这份清单存在的
    全部意义就是不让它发生。宁可这一轮判分不出来, 也不要判出一份把责任算错的分。
    """
    path = directory / EXCLUDED_MANIFEST
    if not path.is_file():
        return {}
    payload, err = _load_json(path)
    if err:
        raise SystemExit(f"排除清单不可读 {path}: {err}")
    if not isinstance(payload, dict):
        raise SystemExit(f"排除清单必须是 {{样本: 原因}} 的对象: {path}")
    out: dict[str, str] = {}
    for sample_id, reason in payload.items():
        if not isinstance(reason, str) or not reason.strip():
            raise SystemExit(f"排除清单里的原因必须是非空字符串: {path} {sample_id!r}")
        out[str(sample_id)] = reason.strip()
    return out


def score_repeat(files: dict[str, Path], truth: dict[str, dict[str, Any]],
                 excluded: dict[str, str] | None = None,
                 code_table: dict[str, str] | None = None) -> dict[str, Any]:
    rows: list[Row] = []
    excluded = excluded or {}
    for sample_id, meta in sorted(truth.items()):
        if sample_id in excluded:
            detail = excluded[sample_id]
            if sample_id in files:
                # 说了不覆盖、却又交了答卷: 两份证据互相矛盾。按排除处理(工具自己声明的),
                # 但把矛盾写进 detail —— 页面上一眼能看出来, 不用去翻两处再对。
                detail = f"{detail}（同时存在答卷文件，按排除处理）"
            rows.append(Row(sample_id, meta["variant"], "excluded", detail))
            continue
        path = files.get(sample_id)
        if path is None:
            rows.append(Row(sample_id, meta["variant"], "invalid_output", "答卷文件缺失"))
            continue
        payload, err = _load_json(path)
        if err:
            rows.append(Row(sample_id, meta["variant"], "invalid_output", err))
            continue
        # `code_table is None` = 本次没给源码，位置保真那一项整项不跑。
        # 给了却缺这一条 = 这条样本没有源码，逐条判 content_na（不是"对得上"）。
        code_text = None if code_table is None else code_table.get(sample_id, "")
        rows.append(judge_sample(payload, meta, code_text))

    report = metrics(rows)
    report["samples"] = [{"sample_id": r.sample_id, "variant": r.variant,
                          "label": r.label, "detail": r.detail} for r in rows]
    return report


# --------------------------------------------------------------------------

def sample_window(truth: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """这批样本覆盖哪段时间 —— PRD §8 的 reports 表要求 metrics 里必须有 window。

    取真值里的 published_at 极值。缺这一列时**不猜**（null 而不是空串），
    并把缺的条数写出来：只用一半样本算出来的"窗口"看起来完整，实际是假的。
    """
    published = sorted(d for d in ((t.get("published_at") or "")[:10] for t in truth.values())
                       if len(d) == 10)
    valid = sorted(v for v in ((t.get("valid_until") or "")[:10] for t in truth.values())
                   if len(v) == 10)
    return {
        "published_at_from": published[0] if published else None,
        "published_at_to": published[-1] if published else None,
        "valid_until_min": valid[0] if valid else None,
        "samples_without_published_at": len(truth) - len(published),
    }


def caveats_for(n_samples: int, window: dict[str, Any],
                n_excluded: int = 0, excluded_excessive: bool = False,
                n_no_answer: int = 0, no_answer_reasons: dict[str, int] | None = None,
                n_answered: int | None = None,
                limits: dict[str, int] | None = None,
                locator_far: int = 0, locator_checked: int = 0) -> list[str]:
    """把"覆盖多少、哪段时间"换成**这批样本真实的数**。

    写死的样本数是报表里最难发现的一种谎：它不会让任何一格数字变错，
    只会让人觉得这份分数适用的范围比实际大。
    """
    start, end = window.get("published_at_from"), window.get("published_at_to")
    if start and end and start == end:
        span = f"公开于 {start}"
    elif start and end:
        span = f"公开于 {start} ~ {end}"
    else:
        span = "部分样本没有公开时间"
    missing = int(window.get("samples_without_published_at") or 0)
    missing_text = f"（其中 {missing} 条缺公开时间）" if missing else ""
    excluded_text = ""
    if n_excluded:
        # 有排除时必须单独写一句: 不然读者以为"20 条样本"就是 20 条都在分里。
        excluded_text = (f"其中 {n_excluded} 条因工具声明不支持该语言/环境未计入分母，"
                         f"分数只代表剩下 {n_samples - n_excluded} 条。")
        if excluded_excessive:
            excluded_text += (f"被排除的已达到 {n_excluded / n_samples:.0%}，"
                              f"超过 {EXCLUDED_LIMIT:.0%}：这份分数不能代表该工具的整体能力，"
                              "只能说明它在剩下那些样本上的表现。")
    no_answer_text = ""
    if n_no_answer:
        # 这句必须自己单独出现：没有它，读者会把"20 条正样本里命中 4 条"读成 20%，
        # 而工具其实只在其中 8 条上给过判断。
        reasons = "、".join(f"{k}×{v}" for k, v in
                           sorted((no_answer_reasons or {}).items()))[:160]
        answered = n_answered if n_answered is not None else n_samples - n_no_answer
        no_answer_text = (
            f"其中 {n_no_answer} 条工具自报「给不出结论」（{reasons}），不计入主分母；"
            f"主分母是它真正作答的 {answered} 条。`silence_as_no_finding` 里那组数字"
            "把这些沉默按「没发现」计，是下界，不是该工具的成绩。")
    limits_text = ""
    if limits:
        parts = "、".join(f"{k}×{v}" for k, v in sorted(limits.items()))
        limits_text = (f"另有 {parts} 条答案是在受限视角下给出的（例如只看到文件前若干字符），"
                       "这些样本上的结论不能推广到整个仓库。")
    locator_text = ""
    if locator_far:
        # 这句说的是"工具自己说的行号，和它自己抄的代码对不上" —— 与"没找到洞"是两件事。
        locator_text = (
            f"核对了 {locator_checked} 条 finding 的代码片段，其中 {locator_far} 条与答卷"
            "自报的行号对不上（片段找得到、但不在报的位置）：这些 finding 的定位不可信，"
            "命中/漏报的判定可能因此失真。")
    return [
        *CAVEATS[:2],
        f"只覆盖 {n_samples} 个样本（{span}）{missing_text}，不代表其他漏洞类型。",
        *CAVEATS[3:],
        *( [excluded_text] if excluded_text else [] ),
        *( [no_answer_text] if no_answer_text else [] ),
        *( [limits_text] if limits_text else [] ),
        *( [locator_text] if locator_text else [] ),
    ]


def build_report(answers_dir: Path, truth_dir: Path,
                 code_table: dict[str, str] | None = None) -> dict[str, Any]:
    """`code_table` = {sample_id: 源码文本}。不给就完全不跑位置保真核对（X17）。"""
    truth = load_truth(truth_dir)
    repeats = discover_repeats(answers_dir)

    per_repeat: dict[str, Any] = {}
    ordered: list[dict[str, Any]] = []
    excluded_any: dict[str, str] = {}   # 至少一轮被排除的样本 -> 原因
    for name, files in repeats.items():
        excluded = load_excluded(_repeat_dir(answers_dir, name))
        unknown = sorted(set(excluded) - set(truth))
        if unknown:
            # 样本 id 写错(少个前导零之类)时, 排除会**静默失效**: 该样本照样按缺答卷记
            # invalid_output, 而清单看起来是写了的。这种错在报表上完全看不出来。
            raise SystemExit(f"排除清单点名了真值里没有的样本({name}): {unknown}")
        excluded_any.update(excluded)
        rep = score_repeat(files, truth, excluded, code_table)
        per_repeat[name] = rep
        ordered.append(rep)

    agg = aggregate(ordered)
    delivered = {sid for files in repeats.values() for sid in files}
    # 被排除的样本本来就没有答卷文件, 它们不是"漏交"。
    missing = sorted(set(truth) - delivered - set(excluded_any))

    invalid_rate = (sum(r["invalid_output"]["k"] for r in ordered)
                    / max(1, sum(r["invalid_output"]["n"] for r in ordered)))
    verdict = "unable_to_adapt" if invalid_rate > INVALID_OUTPUT_LIMIT else "ok"
    excluded_rate = len(excluded_any) / max(1, len(truth))
    window = sample_window(truth)

    # no_answer 按轮统计，报表要一个"这批大概有多少条没答"的代表值：多轮取中位数，
    # 单轮就是它自己。理由分桶取**各轮的并集最大值**，不把某一轮的少数当成结论。
    no_answer_ks = [int(r["no_answer"]["k"]) for r in ordered]
    n_no_answer = (sorted(no_answer_ks)[len(no_answer_ks) // 2]
                   if no_answer_ks else 0)
    no_answer_reasons: dict[str, int] = {}
    for rep in ordered:
        for reason, count in (rep["no_answer"]["reasons"] or {}).items():
            no_answer_reasons[reason] = max(no_answer_reasons.get(reason, 0), int(count))
    n_answered = (sorted(int(r["coverage"]["answered"]) for r in ordered)[0]
                  if ordered else None)
    # X17：逐条 finding 的位置保真度。多轮取各桶最大值（与 reasons 同口径：不把某一轮的
    # 少数当成结论），核对条数取中位（单轮就是它自己）。
    locator: dict[str, int] = {k: 0 for k in LOCATOR_STATUSES}
    locator_checked = []
    for rep in ordered:
        block = rep.get("locator_fidelity") or {}
        locator_checked.append(int(block.get("checked") or 0))
        for key in LOCATOR_STATUSES:
            locator[key] = max(locator[key], int(block.get(key) or 0))
    n_locator_checked = (sorted(locator_checked)[len(locator_checked) // 2]
                         if locator_checked else 0)
    limits: dict[str, int] = {}
    for rep in ordered:
        for limit, count in (rep.get("limits") or {}).items():
            limits[limit] = max(limits.get(limit, 0), int(count))

    return {
        "contract_version": CONTRACT_VERSION,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "repeats": list(repeats),
        "n_samples": len(truth),          # PRD §8: reports.metrics_json 必须有 n_samples
        "window": window,                 # PRD §8: 同上
        "truth_samples": len(truth),      # 旧键，保留给已产出的报告
        # n_samples 是**这批样本一共多少条**; 真正进了分母的是 n_samples - n_excluded。
        # 两个数都报, 因为只看前者会让人以为所有样本都参与打分。
        "n_excluded": len(excluded_any),
        "excluded_reasons": _count_reasons(excluded_any),
        # 工具自报「给不出结论」的条数（多轮取中位）。它和 n_excluded 是两件事：
        # 前者是"扫了但没结论"，后者是"声明不覆盖"。
        "n_no_answer": n_no_answer,
        "no_answer_reasons": no_answer_reasons,
        "n_answered": n_answered,
        "coverage_limits": limits,
        # 位置保真度：核对了几条 finding、其中几条对不上（X17）。checked=0 表示本次没给源码。
        "locator_fidelity": {**locator, "checked": n_locator_checked},
        "answers_missing": missing,
        "aggregate": agg,
        "per_repeat": per_repeat,
        "adaptation_verdict": verdict,
        "adaptation_reason": (
            f"invalid_output 比例 {invalid_rate:.1%} 超过阈值 "
            f"{INVALID_OUTPUT_LIMIT:.0%}，按契约 §6 判「无法适配」"
            if verdict == "unable_to_adapt" else
            f"invalid_output 比例 {invalid_rate:.1%}，在阈值内"
        ),
        "caveats": caveats_for(len(truth), window, len(excluded_any),
                               excluded_rate > EXCLUDED_LIMIT,
                               n_no_answer=n_no_answer,
                               no_answer_reasons=no_answer_reasons,
                               n_answered=n_answered,
                               limits=limits,
                               locator_far=locator["content_far"],
                               locator_checked=n_locator_checked),
    }


def _count_reasons(by_sample: dict[str, str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for reason in by_sample.values():
        out[reason] = out.get(reason, 0) + 1
    return out


def format_summary(report: dict[str, Any]) -> str:
    agg = report["aggregate"]
    lines = [
        f"契约版本 {report['contract_version']} · 重复 {len(report['repeats'])} 轮 "
        f"· 样本 {report['truth_samples']} 条",
    ]
    if report.get("n_excluded"):
        reasons = "、".join(f"{k}×{v}" for k, v in
                           sorted((report.get("excluded_reasons") or {}).items()))
        lines.append(f"（{report['n_excluded']} 条被工具声明为不覆盖，未计入分母：{reasons}）")
    if report["answers_missing"]:
        lines.append(f"⚠️ 缺答卷 {len(report['answers_missing'])} 条: "
                     f"{', '.join(report['answers_missing'][:8])}")

    def fmt(name: str, label: str) -> str:
        entry = agg.get(name) or {}
        if entry.get("median") is None:
            return f"  {label}: 无有效数据"
        ci = entry.get("ci95_of_median_repeat")
        ci_text = f" 95%CI [{ci[0]:.2f}, {ci[1]:.2f}]" if ci else ""
        values = entry.get("values") or []
        k_n = ""
        first = (report["per_repeat"][report["repeats"][0]]["labels"])
        label_key = {"locate_rate": ("strict_hit", "near_hit"),
                     "strict_locate_rate": ("strict_hit",),
                     "false_positive_rate": ("false_positive",)}.get(name)
        if label_key and first is not None:
            k = sum(first.get(x, 0) for x in label_key)
            n = (report["per_repeat"][report["repeats"][0]]["n"]["positives"]
                 if name != "false_positive_rate"
                 else report["per_repeat"][report["repeats"][0]]["n"]["negatives"])
            k_n = f" ({k}/{n})"
        return (f"  {label}: {entry['median']:.4f}{k_n}{ci_text}"
                f"  各轮={values}"
                f"{'  [各轮一致]' if entry.get('identical') else ''}")

    lines += [
        fmt("locate_rate", "定位率 locate_rate (hit+near)"),
        fmt("strict_locate_rate", "严格定位率 strict"),
        fmt("false_positive_rate", "误报率 false_positive"),
        fmt("balanced_accuracy", "平衡准确率 balanced_acc"),
        fmt("answered_rate", "作答率 answered/rows"),
        fmt("no_answer_rate", "没答 no_answer"),
    ]
    if report.get("n_no_answer"):
        # 这一行是给读者的防错垫：上面四个主数字的分母只有作答那些。
        silent = (report["per_repeat"][report["repeats"][0]]
                  ["silence_as_no_finding"])
        lines.append(
            "  ⚠️ 主口径只统计工具真正作答的样本；把 {} 条沉默按「没发现」计入后，"
            "locate={} / FP={}（下界，不是成绩）".format(
                report["n_no_answer"],
                _fmt_value(silent["locate_rate"]["value"]),
                _fmt_value(silent["false_positive_rate"]["value"])))
    if report.get("coverage_limits"):
        lines.append("  受限视角: " + "、".join(
            f"{k}×{v}" for k, v in sorted(report["coverage_limits"].items())))
    fidelity = report.get("locator_fidelity") or {}
    if fidelity.get("checked"):
        # 只报"核对了几条、几条对不上"：这个数不参与任何分数，它是给结果打信誉折扣用的
        lines.append(
            "  finding 位置保真: 核对 {} 条 —— 对得上 {} / 对不上 {} / 无法判断 {} / 无片段 {}".format(
                fidelity["checked"], fidelity["content_ok"], fidelity["content_far"],
                fidelity["content_not_found"], fidelity["content_na"]))
    lines += [
        f"  适配判定: {report['adaptation_verdict']} —— {report['adaptation_reason']}",
        "",
        "必须随数字一起给出的 caveats:",
    ]
    lines += [f"  {i}. {c}" for i, c in enumerate(report["caveats"], 1)]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="第 1 类 LLM 代码审计 判分脚本 v1")
    ap.add_argument("--answers", required=True, type=Path, help="答卷目录")
    ap.add_argument("--truth", required=True, type=Path, help="真值目录")
    ap.add_argument("--out", type=Path, help="报告输出路径（省略则打到 stdout）")
    ap.add_argument("--samples-dir", type=Path,
                    help="样本源码目录（如 runs/run-xxx/samples）；给了才做位置保真核对 X17")
    ap.add_argument("--summary", action="store_true", help="只打印人读摘要")
    args = ap.parse_args(argv)

    for name, path in (("answers", args.answers), ("truth", args.truth)):
        if not path.is_dir():
            print(f"目录不存在: {name} = {path}", file=sys.stderr)
            return 2

    code_table = load_code_dir(args.samples_dir) if args.samples_dir else None
    report = build_report(args.answers, args.truth, code_table)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
        print(f"报告已写入 {args.out}", file=sys.stderr)

    if args.summary or not args.out:
        print(format_summary(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
