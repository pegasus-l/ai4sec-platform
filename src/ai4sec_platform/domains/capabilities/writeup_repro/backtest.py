"""回测:拿一条 pattern 回到**它自己的来源**上跑一遍,看能不能指回第 6 节记录的漏洞位置。

为什么要有这一步
================

pattern 入库时只校验了"引文能在原文找到、三种形态齐全", 从来没有验证过这条规律**能不能指回
它自己的来源**。2026-11-17 手工回测了三条(filelock / MLflow / fastecdsa), 都能命中, 而且 filelock
在修复版(3.20.1 加了 ``O_NOFOLLOW``)上自动不再命中 —— 这说明规律抓的是结构, 不是关键词巧合。

设计口径(与手工实验一致)
========================

1. **用工作目录里还在的源码**: agent 复现时已经拉过 vulnerable 版本, 比事后重拉快、版本也对得上。
   所以回测必须排在清理之前(见 ``executor._finish``)。
2. **检索式由模型生成, 但只准是结构化正则**: 不让模型给 shell 命令 —— 那等于把任意执行交给它。
   规则里只有 ``path_glob`` / ``include[]`` / ``exclude[]`` 三个字段, 平台逐条编译, 编译不过就作废。
3. **目录扫描在沙箱里做**: 平台容器看不到沙箱的文件系统, 由 sidecar 的 ``POST /scan`` 只读扫描。
4. **三种结论**: ``pass``(目标点出现在候选里) / ``fail``(扫到了但目标不在) / ``unverified``
   (没有源码 / 没有位置 / 检索式生成失败)。**fail 不等于这条 pattern 没用** —— 它只说明
   "按这条规律自己的描述, 指不回自己的来源", 所以降级到 catalog、不进 verified, 不删除。
5. 回测失败绝不影响任务结论: 全部包在 try 里, 只落一行日志。
"""

from __future__ import annotations

import json
import os
import re
import sqlite3
import urllib.error
import urllib.request
from typing import Any

from ai4sec_platform.models.router import LLMRouter, LocalRuleProvider

MODEL_PROFILE = "writeup_pattern_backtest"

#: 检索式里正则的长度与条数上限。模型很容易写出一个"什么都匹配"的巨正则, 那等于没检索。
MAX_REGEXES = 4
MAX_REGEX_CHARS = 300

RULE_PROMPT = """你在给一条漏洞规律做**回测**: 把它转成能在源码里跑的检索规则, 让目标文件被圈出来。

给你的是一条已经入库的漏洞规律(invariant / code_feature / audit_entry), 以及目标文件的相对路径。
只输出 JSON:
{
  "path_glob": "*.py",        // 只扫哪些文件, 例如 "*.py" / "*.c" / "*"; 用 fnmatch 语法
  "include": ["\\bO_TRUNC\\b", "os\\.open"],   // 1-4 条正则, **全部**命中才算候选
  "exclude": ["O_NOFOLLOW"]   // 0-4 条正则, 命中任意一条就排除
}

硬规则(违反任意一条, 这份规则作废):
- 正则必须是 **Python `re` 语法**, 不能是 shell 命令, 不能带引号包裹。
- include 至少 1 条; 一共不超过 4 条; 每条不超过 300 字符。
- **不要写只在你这一个文件里出现的字面路径** —— 那是把答案抄进检索式, 回测就没有意义了。
  要按"写法"检索: 用什么函数、什么常量组合、缺哪个防护。
- 排除项用来表达"修好之后就不该命中"的特征(例如 O_NOFOLLOW), 能写就写。
- 目标文件路径只是给你判断语言和写法的提示, **不要**把它写成 include 正则。
"""


def enabled() -> bool:
    """开关。默认开 —— 关掉只用 ``WRITEUP_BACKTEST=0``。"""
    return (os.getenv("WRITEUP_BACKTEST") or "1").strip().lower() not in ("0", "false", "off", "no")


# ---------------------------------------------------------------- 检索式

def build_rule(pattern: dict[str, Any], target_file: str) -> dict[str, Any]:
    """让模型把规律翻成结构化检索式。返回 ``{"status": "ok|no_model|error", "rule": {...}}``。"""
    payload = {
        "invariant": str(pattern.get("invariant") or "")[:1500],
        "code_feature": str(pattern.get("code_feature") or "")[:1500],
        "audit_entry": str(pattern.get("audit_entry") or "")[:800],
        "target_file_hint": str(target_file or "")[:300],
    }
    try:
        provider = LLMRouter().provider_for(MODEL_PROFILE)
        if isinstance(provider, LocalRuleProvider):
            return {"status": "no_model", "rule": {}}
        response = provider.complete_json(prompt=RULE_PROMPT, payload=payload)
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "rule": {}, "reason": str(exc)[:300]}
    result = response.get("result") if isinstance(response, dict) and "result" in response else response
    rule = normalize_rule(result)
    if rule is None:
        return {"status": "error", "rule": {}, "reason": "检索式不合法(正则编译不过/条数为空/超长)"}
    return {"status": "ok", "rule": rule}


def normalize_rule(raw: Any) -> dict[str, Any] | None:
    """校验并收敛模型给的规则。**所有正则都要编译通过**才放行。"""
    if not isinstance(raw, dict):
        return None
    glob = str(raw.get("path_glob") or "*").strip() or "*"
    if len(glob) > 60:
        return None
    include = [str(x).strip() for x in (raw.get("include") or []) if str(x).strip()]
    exclude = [str(x).strip() for x in (raw.get("exclude") or []) if str(x).strip()]
    if not include or len(include) > MAX_REGEXES or len(exclude) > MAX_REGEXES:
        return None
    for regex in include + exclude:
        if len(regex) > MAX_REGEX_CHARS:
            return None
        try:
            re.compile(regex)
        except re.error:
            return None
    return {"path_glob": glob, "include": include, "exclude": exclude}


# ---------------------------------------------------------------- 目标定位

def target_suffixes(location_file: str) -> list[str]:
    """把 ``src/filelock/_unix.py`` 变成几个可匹配的后缀。

    报告里的路径来自原文, 而沙箱里的实际路径可能前面挂了包目录(``.venv/lib/python3.11/
    site-packages/filelock/_unix.py``), 所以按"由长到短"的后缀匹配, 长的优先。
    """
    parts = [p for p in str(location_file or "").strip().replace("\\", "/").strip("/").split("/") if p.strip()]
    if not parts:
        return []
    out: list[str] = []
    for size in range(min(len(parts), 3), 0, -1):
        out.append("/".join(parts[-size:]))
    return out


# ---------------------------------------------------------------- 沙箱扫描

def janitor_base() -> str:
    return os.getenv("WRITEUP_JANITOR_URL") or (
        (os.getenv("WRITEUP_REPRO_API_URL") or "http://repro-writeup:4096").rsplit(":", 1)[0] + ":4098"
    )


def scan(task_id: int, rule: dict[str, Any], suffixes: list[str], *, timeout: int = 60) -> dict[str, Any]:
    """请 sidecar 在工作目录里按规则扫描。返回 ``{"status": "ok|no_workspace|error", ...}``。"""
    body = json.dumps({
        "task_id": int(task_id),
        "path_glob": rule.get("path_glob") or "*",
        "include": list(rule.get("include") or []),
        "exclude": list(rule.get("exclude") or []),
        "target_suffixes": list(suffixes),
    }).encode()
    req = urllib.request.Request(janitor_base().rstrip("/") + "/scan", data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    from ai4sec_platform.pipelines.steps import repro as repro_step

    for key, value in repro_step._headers(os.getenv("WRITEUP_REPRO_PASSWORD", "")).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as exc:
        return {"status": "error", "reason": f"sidecar HTTP {exc.code}: {exc.read().decode()[:200]}"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "reason": str(exc)[:300]}


# ---------------------------------------------------------------- 主流程

def backtest_pattern(
    pattern: dict[str, Any],
    location_file: str,
    task_id: int,
) -> dict[str, Any]:
    """跑一次回测。返回值直接写进 ``writeup_repro_patterns.backtest_json``。"""
    result: dict[str, Any] = {
        "status": "unverified", "reason": "", "target_file": str(location_file or ""),
        "candidates": 0, "target_rank": 0, "files_scanned": 0,
    }
    suffixes = target_suffixes(location_file)
    if not suffixes:
        result["reason"] = "报告第 6 节没有给出文件位置, 无从回测"
        return result

    built = build_rule(pattern, location_file)
    if built.get("status") != "ok":
        result["reason"] = f"检索式生成失败: {built.get('reason') or built.get('status')}"
        return result
    rule = built["rule"]
    result["rule"] = rule

    scanned = scan(task_id, rule, suffixes)
    if scanned.get("status") != "ok":
        result["reason"] = f"扫描失败: {scanned.get('reason') or scanned.get('status')}"
        return result

    result["files_scanned"] = int(scanned.get("files_scanned") or 0)
    result["candidates"] = int(scanned.get("candidates_count") or 0)
    result["sample"] = list(scanned.get("sample") or [])[:5]
    if scanned.get("target_hit"):
        result["status"] = "pass"
        result["target_rank"] = int(scanned.get("target_rank") or 0)
        result["reason"] = "目标文件出现在候选集里"
    elif not result["candidates"]:
        result["status"] = "unverified"
        result["reason"] = "检索式没有圈出任何候选(规则太窄, 说明不了对错)"
    else:
        result["status"] = "fail"
        result["reason"] = "扫到了文件, 但目标文件不在候选集里"
    return result


def store(conn: sqlite3.Connection, pattern_id: int, result: dict[str, Any]) -> None:
    conn.execute(
        "UPDATE writeup_repro_patterns SET backtest_status = ?, backtest_json = ?, backtested_at = ?"
        " WHERE id = ?",
        (
            str(result.get("status") or ""),
            json.dumps(result, ensure_ascii=False),
            _now(),
            int(pattern_id),
        ),
    )
    conn.commit()
    if result.get("status") == "fail":
        # 指不回自己来源的规律不进 verified, 但留在库里(报告已经写了它)。
        conn.execute("UPDATE writeup_repro_patterns SET provenance = 'llm_extracted' WHERE id = ?",
                     (int(pattern_id),))
        conn.commit()


def _now() -> str:
    from datetime import datetime, timezone

    return f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"
