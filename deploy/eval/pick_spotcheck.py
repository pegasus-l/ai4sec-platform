#!/usr/bin/env python3
"""D5 的另一半：人工抽检取样器。

PRD §9（`ai4sec-capability-eval-prd-20261031.md:673-674`，2026-11-02 定）：
**每轮随机抽 10 条，一致率 ≥90%（≥9/10）才认这一轮的结论，≤8/10 整轮标「参考」。**

> 为什么是 10 条不是 3 条：3 条时 90% 只有 67% / 100% 两档 —— 等于"错一条就整轮作废"，
> 门槛变成了噪声；10 条才第一次出现"允许错 1 条"。**这个数不许随手改小。**

这条一直没有承载它的东西 —— 报表里既没有抽检记录，也没有"抽了哪几条"。本文件补上取样这一半：
把该轮的十条样本连同**工具答卷、真值、自动判分**一起摊开，由人逐条写「同意 / 不同意」。

抽哪几条**不是取前十条**（前十条常是同一语言/同一目录，测不出跨语言的翻译失真），
按风险分层取，层内用 `(run_id, sample_id)` 派生的随机序 —— **同一轮重复取样结果一致**（可复查）：

1. **invalid_output** —— 转换层出错的重灾区（最多 2 条）；
2. **正样本里判成 hit 的** —— 假命中的代价最高（最多 2 条）；
3. **正样本里判成 miss / other_hunk 的** —— 假阴性（最多 3 条）；
4. 余下的从**负样本**里补（判 `false_positive` 的优先）。

> 这份表里**有真值**。它是给人看的卷宗，不是给适配 agent 的输入 —— 不要塞进 eval 容器。
> 一致率 = `同意条数 / 抽检条数`；`< 0.9`（即 ≤8/10）⇒ 该轮报表按 PRD 标「参考」。

用法（平台容器内，读 live 库，只读打开）：
    python3 /app/deploy/eval/pick_spotcheck.py --run-id 11
    python3 /app/deploy/eval/pick_spotcheck.py --run-id 11 --format json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sqlite3
import sys

# 与 score.py 的标签同名；这里只做展示，不重算分数。
HIT_LABELS = {"strict_hit", "near_hit"}


def _order_key(run_id: int, sample_id: int) -> str:
    """同一轮取样可复现：不依赖 dict/集合顺序，也不依赖 sqlite 的返回序。"""
    return hashlib.sha256(f"{run_id}:{sample_id}".encode()).hexdigest()


def _load_samples(conn: sqlite3.Connection) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for key, gt_json in conn.execute(
            "SELECT sample_key, ground_truth_json FROM capability_eval_samples"):
        try:
            blob = json.loads(gt_json) if isinstance(gt_json, str) else (gt_json or {})
        except (TypeError, ValueError):
            blob = {}
        out[key] = blob
    return out


def _row_label(report: dict, sample_key: str) -> tuple[str, str]:
    """从报表里取这一条的自动判分。报表没有这一轮的逐条结论时返回 ('?', '')。"""
    for repeat in (report.get("per_repeat") or {}).values():
        for sample in repeat.get("samples") or []:
            if sample.get("sample_id") == sample_key:
                return str(sample.get("label") or "?"), str(sample.get("detail") or "")
    return "?", ""


def _load_report(conn: sqlite3.Connection, run_id: int) -> dict:
    row = conn.execute(
        "SELECT metrics_json FROM capability_eval_reports WHERE run_id=?", (run_id,)).fetchone()
    if not row:
        return {}
    try:
        return json.loads(row[0]) if isinstance(row[0], str) else (row[0] or {})
    except (TypeError, ValueError):
        return {}


def collect(conn: sqlite3.Connection, run_id: int, count: int) -> list[dict]:
    samples = _load_samples(conn)
    report = _load_report(conn, run_id)

    answers: dict[str, dict] = {}
    for sample_id, answer_json, raw in conn.execute(
            "SELECT sample_id, answer_json, raw_answer FROM capability_eval_answers"
            " WHERE run_id=? ORDER BY sample_id", (run_id,)):
        key = f"s_{int(sample_id):04d}"
        payload = answer_json
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except (TypeError, ValueError):
                payload = None
        answers[key] = {"answer": payload, "raw": raw}

    rows = []
    for key, entry in answers.items():
        truth = samples.get(key) or {}
        gt = truth.get("gt") or {}
        label, detail = _row_label(report, key)
        rows.append({
            "sample_key": key,
            "variant": truth.get("variant") or ("pre" if int(key[2:]) % 2 else "post"),
            "auto_label": label,
            "auto_detail": detail,
            "answer": entry["answer"],
            "truth": gt,
            "patch_hunks": truth.get("patch_hunks") or [],
            "_order": _order_key(run_id, int(key[2:])),
        })

    # ---- 分层：风险高的先看 ----
    picked: list[dict] = []

    def take(bucket, n=1):
        for row in sorted(bucket, key=lambda r: r["_order"]):
            if len(picked) >= count:
                return
            if n <= 0:
                return
            if row in picked:
                continue
            picked.append(row)
            n -= 1

    take([r for r in rows if r["auto_label"] == "invalid_output"], 2)
    take([r for r in rows if r["variant"] == "pre" and r["auto_label"] in HIT_LABELS], 2)
    take([r for r in rows if r["variant"] == "pre"
          and r["auto_label"] in {"miss", "other_hunk"}], 3)
    take([r for r in rows if r["variant"] == "post"
          and r["auto_label"] == "false_positive"], count)
    take([r for r in rows if r["variant"] == "post"], count)
    take([r for r in rows if r not in picked], count)   # 兜底：什么标签都没有时也要凑够

    return picked[:count]


def _fmt_answer(answer) -> str:
    if not isinstance(answer, dict):
        return "（答卷不是合法 JSON）"
    findings = answer.get("findings") or []
    if not findings:
        return f"`found={answer.get('found')}`，无 finding"
    lines = [f"`found={answer.get('found')}`，{len(findings)} 条 finding："]
    for index, finding in enumerate(findings, 1):
        evidence = str(finding.get("evidence") or "").replace("\n", " ⏎ ")
        if len(evidence) > 300:
            evidence = evidence[:300] + "…"
        lines.append(
            f"{index}. `{finding.get('file')}:{finding.get('line_start')}-{finding.get('line_end')}`"
            f" cwe={finding.get('type_cwe') or '—'} — {evidence}")
    return "\n".join(lines)


def render_markdown(rows: list[dict], run_id: int) -> str:
    out = [f"# 第 1 类评测人工抽检 — run {run_id}", "",
           f"PRD §9：每轮随机抽 10 条，**一致率 ≥90%（≥9/{len(rows)}）才认这一轮的结论**，"
           "否则整轮标「参考」。",
           "逐条在「人工判定」栏写 **同意** 或 **不同意 + 理由**。", ""]
    for index, row in enumerate(rows, 1):
        truth = row["truth"]
        out.append(f"## {index}. `{row['sample_key']}`（{row['variant']}）"
                   f" — 自动判分：**{row['auto_label']}**")
        if row["auto_detail"]:
            out.append(f"> {row['auto_detail']}")
        out.append("")
        out.append("**工具答卷**")
        out.append("")
        out.append(_fmt_answer(row["answer"]))
        out.append("")
        out.append("**真值**")
        out.append("")
        out.append(f"- file: `{truth.get('file')}`")
        out.append(f"- function: `{truth.get('function') or '—'}`")
        out.append(f"- lines: `{truth.get('line_start')}-{truth.get('line_end')}`")
        out.append(f"- cwe: `{truth.get('cwe') or '—'}`")
        if row["patch_hunks"]:
            out.append(f"- patch_hunks: `{row['patch_hunks']}`")
        out.append("")
        out.append("**人工判定**：☐ 同意 ☐ 不同意 —— 理由：")
        out.append("")
        out.append("---")
        out.append("")
    out.append("## 汇总")
    out.append("")
    out.append("| 样本 | 自动判分 | 人工 |")
    out.append("|---|---|---|")
    for row in rows:
        out.append(f"| `{row['sample_key']}` | {row['auto_label']} |  |")
    out.append("")
    need = math.ceil(0.9 * len(rows))
    out.append(f"一致率 = 同意条数 / {len(rows)}；需要 **≥{need} 条同意**（最多容忍 "
               f"{len(rows) - need} 条不同意），否则该轮报表标「参考」。")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", type=int, required=True)
    # PRD §9 定的是 10 条。留 --count 只为在小样本轮次上临时缩，正常不许改小。
    ap.add_argument("--count", type=int, default=10)
    ap.add_argument("--format", choices=["markdown", "json"], default="markdown")
    ap.add_argument("--db", default="")
    a = ap.parse_args()

    db_path = a.db
    if not db_path:
        from ai4sec_platform.core.config import load_settings
        db_path = load_settings().database_path
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    rows = collect(conn, a.run_id, a.count)
    if not rows:
        print("这一轮没有任何答卷", file=sys.stderr)
        return 1
    if a.format == "json":
        print(json.dumps(rows, ensure_ascii=False, indent=1))
    else:
        print(render_markdown(rows, a.run_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
