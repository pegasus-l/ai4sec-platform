#!/usr/bin/env python3
"""secondpass → 评测契约适配层。

与适配 agent 第一版 shim 的差别(2026-11-03 修正, 三条都是"把工具的输出读错了"):

1. **不再压工具的迭代次数**。第一版传 `max_iterations=1`, 而工具默认是 6
   (`app/agent.py: MAX_TOOL_ITERATIONS = 6`)。循环条件是契约明令不许改的东西,
   压到 1 等于在测一个残废配置 —— run 9 的 0/13 就是在那个配置下得出的, 不能用。
2. **认包装层与 evidence 里的位置**。工具的结构化 finding 只有
   `finding_type/evidence/confidence/suggested_fix/detection_method`, **没有行号**;
   行号只出现在模型写进 `evidence` 的那段 JSON 里(`{"finding": {"path":…, "line":…}}`)。
   第一版只看顶层, 于是每条都 `line_start=null` → 整份答卷被判 invalid_output。
3. **`type_cwe` 只放真正的 CWE 编号**。第一版把 `rule_id`(`secondpass.logic-review`)
   塞进去, 不匹配 `CWE-\\d+` 同样会让整份答卷作废。
4. **把工具自己的 venv 放进 PATH**(等价 `source .venv/bin/activate`)。工具的
   `_resolve_semgrep()` 先找 `sys.executable` 的同目录, 而 `.venv/bin/python` 是符号链接,
   `resolve()` 之后落到 `/usr/local/bin`; 不激活 venv, semgrep 恒找不到, 静态扫描每条都
   以 `ScanError` 收场 —— run 10 的 raw/*.stderr 里每条都是 `tool=run_static_scan
   error=ScanError duration_ms=0.2`。
5. **认 evidence 第一行的 `{path}:{line}` 前缀**。一条答卷里往往有 2~3 条 finding, 只有第一条的
   evidence 是 `{"finding": {...}}` 的 JSON, 其余是工具 `_finding_evidence()` 拼的纯文本
   `/<abs>/code.c:158` + message + snippet。只解析 JSON 的话, 第 2 条起行号全空 ——
   而契约是"任何一条 finding 不合法 → 整份答卷作废", 于是 2 条以上 finding 的答卷**全废**。

诚实的边界: 工具没给行号时, **不编**。这样的 finding 会让答卷落成 invalid_output
(契约没有"找到了但报不出位置"这种形态), 这是工具的真实表现, 不是适配层造出来的。
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys

CWE_RE = re.compile(r"CWE-\d+")
MAX_FINDINGS = 5


def as_dict(x):
    if hasattr(x, "model_dump"):
        try:
            return x.model_dump()
        except Exception:  # noqa: BLE001
            pass
    if hasattr(x, "dict"):
        try:
            return x.dict()
        except Exception:  # noqa: BLE001
            pass
    if isinstance(x, dict):
        return x
    return {"evidence": str(x)}


def _path_line_from_evidence(text):
    """evidence 的第一行是 `{path}:{line}`。

    这是工具自己的格式: `agent.py:_finding_evidence()` 拼的就是
    `f"{finding['path']}:{finding['line']}"` + 换行 + message + 换行 + snippet。
    工具的 Finding schema 里没有独立行号字段, 所以除了这条前缀没有别的地方能拿到位置。
    """
    first = (text or "").strip().split("\n", 1)[0].strip()
    if ":" not in first:
        return None
    _path, _, tail = first.rpartition(":")
    tail = tail.strip()
    if not tail.isdigit():
        return None
    return int(tail)


def _unwrap(d):
    """拆掉 {"finding": {...}, "explanation": ...} 这一层, 并尝试从 evidence 里取位置。"""
    d = dict(d or {})
    inner = d.get("finding")
    if isinstance(inner, dict):
        merged = dict(inner)
        for key, value in d.items():
            merged.setdefault(key, value)
        d = merged
    ev = d.get("evidence")
    if isinstance(ev, str):
        text = ev.strip()
        if text.startswith("{"):
            try:
                blob = json.loads(text)
            except (ValueError, TypeError):
                blob = None
            if isinstance(blob, dict):
                inner = blob.get("finding")
                if isinstance(inner, dict):
                    for key in ("line", "line_start", "path", "file", "message",
                                "rule_id", "severity", "snippet", "function"):
                        if key in inner and not d.get(key):
                            d[key] = inner[key]
                if not d.get("message") and isinstance(blob.get("explanation"), str):
                    d["message"] = blob["explanation"]
        # 普通文本形态: `/<abs>/code.c:158\nmessage\nsnippet`。拿不到就留空 (不编)。
        if not _int_line(d, "line_start", "start_line", "line", "line_number"):
            line = _path_line_from_evidence(text)
            if line is not None:
                d["line"] = line
    return d


def flatten_findings(sec):
    candidates = []
    rr = sec.get("review_result") or {}
    if isinstance(rr, dict) and isinstance(rr.get("findings"), list):
        candidates.extend(rr.get("findings") or [])
    for key in ("accepted", "needs_review", "findings", "all_findings"):
        value = sec.get(key)
        if isinstance(value, list):
            candidates.extend(value)
    seen = set()
    out = []
    for item in candidates:
        d = _unwrap(as_dict(item))
        key = (str(d.get("evidence")), str(d.get("finding_type")), str(d.get("line")),
               str(d.get("line_start")))
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    return out


def _int_line(d, *keys):
    for key in keys:
        value = d.get(key)
        if isinstance(value, bool):
            continue
        try:
            value = int(value)
        except (TypeError, ValueError):
            continue
        if value >= 1:
            return value
    return None


def to_finding(d, rel_path):
    start = _int_line(d, "line_start", "start_line", "line", "line_number")
    end = _int_line(d, "line_end", "end_line", "line")
    if start is not None and (end is None or end < start):
        end = start
    cwe = None
    for key in ("type_cwe", "cwe", "rule_id", "finding_type"):
        value = d.get(key)
        if isinstance(value, str) and CWE_RE.search(value):
            cwe = CWE_RE.search(value).group(0)
            break
    evidence = d.get("evidence") or d.get("message") or json.dumps(d, default=str)
    out = {
        "file": rel_path,
        "line_start": start,
        "line_end": end,
        "type_cwe": cwe,
        "evidence": str(evidence)[:2000],
    }
    # 契约里 function 出现就必须是字符串; 拿不到就整个键不写, 不能写 null。
    func = d.get("function") or d.get("function_name")
    if isinstance(func, str) and func.strip():
        out["function"] = func.strip()
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--path", required=True)
    ap.add_argument("--tool-dir", default=os.getcwd())
    a = ap.parse_args()

    logging.disable(logging.CRITICAL)
    os.environ.setdefault("LLM_PROVIDER", "eval")
    # 等价于 `source .venv/bin/activate`: 工具自己的 _resolve_semgrep() 先看
    # sys.executable 的同目录, 而 .venv/bin/python 是符号链接, resolve() 之后
    # 指向 /usr/local/bin, 于是只能用 PATH 找 semgrep。不把 venv 的 bin 放进
    # PATH, 静态扫描恒以 ScanError 收场 —— 那是"没激活虚拟环境", 不是工具不行。
    venv_bin = os.path.join(a.tool_dir, ".venv", "bin")
    os.environ["PATH"] = venv_bin + os.pathsep + os.environ.get("PATH", "")
    sys.path.insert(0, a.tool_dir)
    from app.agent import review_path  # noqa: E402

    # 不传 max_iterations: 用工具自己的默认值(6)。压它就是在改工具的循环条件。
    result = review_path(a.file, memory_enabled=False)
    sec = result.get("security") or {}
    raw = flatten_findings(sec)
    findings = [to_finding(d, a.path) for d in raw[:MAX_FINDINGS]]
    # 契约只允许 found / findings 两个顶层字段, 任何附加说明都会被判 invalid。
    print(json.dumps({"found": bool(findings), "findings": findings}, ensure_ascii=False))
    # 诊断走 stderr(runner 会落到 raw/*.stderr), 不进答卷: 事后要能分清
    # "没扫" "扫了没有" "截断到 12k 字符没看完" "模型答非所问"。
    diag = {
        "static_scan_error": sec.get("static_scan_error"),
        "static_scan_empty": sec.get("static_scan_empty"),
        "inconclusive": sec.get("inconclusive"),
        "logic_review_status": sec.get("logic_review_status"),
        "source_truncated": sec.get("source_truncated"),
        "model": sec.get("model"),
        "raw_findings": len(raw),
        "message": str(sec.get("message") or "")[:200],
    }
    print("[shim] " + json.dumps(diag, ensure_ascii=False), file=sys.stderr)


if __name__ == "__main__":
    main()
