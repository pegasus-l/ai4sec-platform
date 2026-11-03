#!/usr/bin/env python3
"""答卷保真度自查（D5 的一半，另一半是人工抽检）。

它回答的是一个问题：**转换层有没有替工具编位置？**

判分只读答卷，所以"答卷里的行号是不是工具真的说过的那一行"在报表上是看不出来的 ——
一个把行号猜成 1 的 shim 和一个忠实转换的 shim，产出的报表长得一模一样（都是 miss）。

做法：工具的 finding 原文里位置只有两种形态（见 `secondpass_shim.py` 头注释）：
  `/<abs>/code.c:158` 前缀，或 `{"finding": {"line": 158}}` 的 JSON。
逐条把它和答卷里的 `line_start` 对比。对不上 = 转换层在编，不是工具报错。

用法（在平台容器内跑，读的是 live 库，只读打开）：
    python3 /app/deploy/eval/verify_answers.py --run-id 11
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys


def _norm_path(value) -> str:
    text = str(value or "").strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def _locator_from_evidence(text: str):
    """返回 (kind, line)：kind ∈ {"prefix", "json", None}。拿不到行号返回 (None, None)。"""
    first = (text or "").strip()
    if not first:
        return None, None
    if first.startswith("{"):
        try:
            blob = json.loads(first)
        except (ValueError, TypeError):
            blob = None
        if isinstance(blob, dict):
            inner = blob.get("finding") if isinstance(blob.get("finding"), dict) else blob
            try:
                return "json", int(inner.get("line"))
            except (TypeError, ValueError):
                return None, None
    head = first.split("\n", 1)[0].strip()
    if ":" in head:
        _path, _, tail = head.rpartition(":")
        if tail.strip().isdigit():
            return "prefix", int(tail.strip())
    return None, None


def check(conn: sqlite3.Connection, run_id: int) -> dict:
    samples = {}
    for row in conn.execute(
            "SELECT sample_id, ground_truth_json FROM capability_eval_samples"):
        try:
            gt = json.loads(row[1]) if isinstance(row[1], str) else (row[1] or {})
        except (TypeError, ValueError):
            gt = {}
        samples[row[0]] = gt.get("gt") or {}

    stats = {"answers": 0, "findings": 0, "no_locator": 0,
             "line_mismatch": 0, "file_mismatch": 0, "evidence_json": 0}
    problems: list[str] = []

    rows = conn.execute(
        "SELECT sample_id, repeat_index, answer_json, raw_answer"
        " FROM capability_eval_answers WHERE run_id=? ORDER BY sample_id, repeat_index",
        (run_id,)).fetchall()
    for sample_id, repeat, answer_json, raw_answer in rows:
        stats["answers"] += 1
        payload = answer_json if isinstance(answer_json, dict) else None
        if payload is None and isinstance(raw_answer, str):
            try:
                payload = json.loads(raw_answer)
            except (TypeError, ValueError):
                payload = None
        if not isinstance(payload, dict):
            problems.append(f"{sample_id} r{repeat}: 答卷不是 JSON 对象")
            continue
        gt = samples.get(sample_id) or {}
        for index, finding in enumerate(payload.get("findings") or []):
            stats["findings"] += 1
            tag = f"{sample_id} r{repeat} findings[{index}]"
            got_file = _norm_path(finding.get("file"))
            want_file = _norm_path(gt.get("file"))
            if want_file and got_file != want_file:
                stats["file_mismatch"] += 1
                problems.append(f"{tag}: file={got_file!r} 期望 {want_file!r}")
            kind, line = _locator_from_evidence(finding.get("evidence"))
            if kind == "json":
                stats["evidence_json"] += 1
            if line is None:
                stats["no_locator"] += 1
                problems.append(f"{tag}: evidence 里没有可核对的位置（无法验证，不等于错）")
                continue
            if line != finding.get("line_start"):
                stats["line_mismatch"] += 1
                problems.append(
                    f"{tag}: 工具说第 {line} 行，答卷写的是 {finding.get('line_start')}")
    stats["problems"] = problems
    return stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-id", type=int, required=True)
    ap.add_argument("--db", default="")
    a = ap.parse_args()

    db_path = a.db
    if not db_path:
        from ai4sec_platform.core.config import load_settings
        db_path = load_settings().database_path
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

    stats = check(conn, a.run_id)
    for key in ("answers", "findings", "evidence_json", "no_locator",
                "line_mismatch", "file_mismatch"):
        print(f"{key}: {stats[key]}")
    for line in stats["problems"][:40]:
        print("  -", line)
    if len(stats["problems"]) > 40:
        print(f"  ... 还有 {len(stats['problems']) - 40} 条")
    # 只有"编位置"和"写错文件"是硬失败; 拿不到位置是工具没给, 不算转换层的错。
    return 1 if (stats["line_mismatch"] or stats["file_mismatch"]) else 0


if __name__ == "__main__":
    sys.exit(main())
