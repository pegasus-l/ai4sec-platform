#!/usr/bin/env python3
"""参考审计器 —— **测试夹具, 不是产品, 不出分数**。

它存在的唯一目的: 在接真工具(47504)之前, 先把「平台 → 执行位 → 答卷 → 判分 → 页面」
整条链跑通。没有它, 一个已发生的链路 bug 会被误读成"这个工具审计能力不行"。

判据是**纯正则**的: 看到 `os.system(` 就报、没看到就说没有。所以:

  * 它输出的分数**不许**进产品报表(冒烟后要删掉那条 run 与它挂的 item);
  * 它的"正确率"大致等于"这批样本里用 os.system 修掉的洞占多少", 没有意义。

它读文件、写 JSON, 不联网、不调模型。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# 只在"这一行有明显的危险调用"时报。宁可漏报: 夹具的任务是打通链路, 不是刷分数。
RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bos\.system\s*\("), "CWE-78"),
    (re.compile(r"\bsubprocess\.[a-z_]+\([^)]*shell\s*=\s*True"), "CWE-78"),
    (re.compile(r"(?<![\w.])eval\s*\("), "CWE-95"),
    (re.compile(r"(?<![\w.])exec\s*\("), "CWE-95"),
    (re.compile(r"\bpickle\.loads\s*\("), "CWE-502"),
    (re.compile(r"\byaml\.load\s*\((?![^)]*Loader\s*=\s*yaml\.SafeLoader)"), "CWE-502"),
    (re.compile(r"\bopen\s*\([^)]*\+\s*[a-z_]+"), "CWE-22"),
    (re.compile(r"\bexecute\s*\(\s*[a-zA-Z_][\w.]*\s*%"), "CWE-89"),
)


def _function_of(lines: list[str], index: int) -> str:
    """往上找最近的 def —— 报位置时函数名比行号好读, 也更抗行号漂移。"""
    for back in range(index, -1, -1):
        match = re.match(r"\s*(?:async\s+)?def\s+([A-Za-z_]\w*)", lines[back])
        if match:
            return match.group(1)
    return ""


def audit(path: Path, reported_as: str = "") -> dict:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"read failed: {exc}", file=sys.stderr)
        return {"found": False, "findings": []}

    lines = text.splitlines()
    findings = []
    for index, line in enumerate(lines):
        if line.lstrip().startswith(("#", "//", "*")):
            continue
        for pattern, cwe in RULES:
            if pattern.search(line):
                findings.append({
                    "file": reported_as or path.name,
                    "function": _function_of(lines, index),
                    "line_start": index + 1,
                    "line_end": index + 1,
                    "type_cwe": cwe,
                    "evidence": line.strip()[:200],
                })
                break
        if len(findings) >= 5:      # 契约 §3: 最多 5 条
            break
    return {"found": bool(findings), "findings": findings}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="参考审计器(测试夹具)")
    parser.add_argument("--file", required=True)
    # 原仓库相对路径。盘上的文件叫 code.py, 而判分比的是原路径 ——
    # 不传这个, 一次真命中会被判成 miss(2026-11-02 冒烟实测踩到)。
    parser.add_argument("--path", default="")
    args = parser.parse_args(argv)
    print(json.dumps(audit(Path(args.file), args.path), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
