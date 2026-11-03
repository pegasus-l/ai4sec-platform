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

    extra = set(payload) - {"found", "findings"}
    if extra:
        errs.append(f"不允许的顶层字段: {sorted(extra)}")
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


def judge_sample(answer: Any, truth: dict[str, Any]) -> Row:
    sample_id = truth.get("sample_id", "?")
    variant = truth.get("variant", "pre")

    errs = validate_answer(answer)
    if errs:
        return Row(sample_id, variant, "invalid_output", "; ".join(errs[:3]))

    raw = answer.get("findings") or []
    found = bool(answer.get("found"))
    findings = raw[:MAX_FINDINGS]
    truncated = f"（原有 {len(raw)} 条，按契约 §3.1 #2 截断到 {MAX_FINDINGS} 条）" \
        if len(raw) > MAX_FINDINGS else ""

    if variant == "post":
        return Row(sample_id, variant,
                   "false_positive" if found else "true_negative",
                   f"负样本报出 {len(findings)} 条{truncated}" if found else "")

    if not found or not findings:
        return Row(sample_id, variant, "miss", "正样本未报出")

    gt = truth["gt"]
    hunks = truth.get("patch_hunks") or []
    best, best_rank = "miss", 0
    for finding in findings:
        label = grade_finding(finding, gt, hunks)
        rank = _RANK.get(label, 0)
        if rank > best_rank:
            best, best_rank = label or "miss", rank
    return Row(sample_id, variant, best, truncated)


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


def tally(rows: list[Row]) -> dict[str, int]:
    keys = ["strict_hit", "near_hit", "other_hunk", "miss",
            "false_positive", "true_negative", "invalid_output"]
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
    positives = [r for r in scorable
                 if r.variant == "pre" and r.label != "invalid_output"]
    negatives = [r for r in scorable
                 if r.variant == "post" and r.label != "invalid_output"]

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
    }


def _reason_counts(rows: list[Row]) -> dict[str, int]:
    """排除原因分组。报表要能回答"排除掉的都是些什么", 不然一个总数就是在让人猜。"""
    out: dict[str, int] = {}
    for row in rows:
        if row.label == "excluded":
            out[row.detail] = out.get(row.detail, 0) + 1
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
                 excluded: dict[str, str] | None = None) -> dict[str, Any]:
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
        rows.append(judge_sample(payload, meta))

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
                n_excluded: int = 0, excluded_excessive: bool = False) -> list[str]:
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
    return [
        *CAVEATS[:2],
        f"只覆盖 {n_samples} 个样本（{span}）{missing_text}，不代表其他漏洞类型。",
        *CAVEATS[3:],
        *( [excluded_text] if excluded_text else [] ),
    ]


def build_report(answers_dir: Path, truth_dir: Path) -> dict[str, Any]:
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
        rep = score_repeat(files, truth, excluded)
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
                               excluded_rate > EXCLUDED_LIMIT),
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
    ap.add_argument("--summary", action="store_true", help="只打印人读摘要")
    args = ap.parse_args(argv)

    for name, path in (("answers", args.answers), ("truth", args.truth)):
        if not path.is_dir():
            print(f"目录不存在: {name} = {path}", file=sys.stderr)
            return 2

    report = build_report(args.answers, args.truth)

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
