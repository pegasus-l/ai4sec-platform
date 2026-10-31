"""复现报告解析与日志分类工具。

历史包袱已清（2026-10-31）：这里原本还放着旧版容器编排器 ReproRunner / ReproManager、
两套已经没人调用的 prompt 构建器。复现改由独立复现服务承担后它们全部失效，故删除。
线上唯一生效的复现提示词是 `pipelines/steps/repro.py::_build_repro_prompt`。

现在留下的都是被生产代码引用的纯函数：
- `classify_log_line` —— 复现日志分色（app/api/capabilities.py）
- `extract_report` / `enforce_report_acceptance` / `task_status_from_report`
  —— 报告提取与验收（pipelines/steps/repro.py、adapters/repro_results.py）
- `strip_ansi` / `redact_sensitive_log_value` —— 日志清洗与脱敏
"""
from __future__ import annotations

import copy
import json
import os
import re

from ai4sec_platform.core.env import load_env_file

load_env_file()

# 复现服务使用的 LLM key：仅用于把日志里出现的 key 打码
REPRO_LLM_API_KEY = os.environ.get("REPRO_LLM_API_KEY", "")


# ============================================================================
# 输出行分类（给大屏/SSE 上色用）- 迁自旧 repro.py 第 623-726 行
# ============================================================================
_ANSI_RE = re.compile(r'\x1b\[[0-9;?]*[a-zA-Z]')
_BARE_ANSI_RE = re.compile(r'\[[0-9]{1,3}(?:;[0-9]{1,3})*m')


def strip_ansi(line: str) -> str:
    """去掉终端 ANSI 转义码（网页面板自己上色，不需要这些码）。"""
    line = _ANSI_RE.sub('', line)
    line = _BARE_ANSI_RE.sub('', line)
    return line


def redact_sensitive_log_value(value: str) -> str:
    if REPRO_LLM_API_KEY:
        value = value.replace(REPRO_LLM_API_KEY, "<redacted>")
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "<redacted>", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", "<redacted-jwt>", value)
    return value


def enforce_report_acceptance(report: dict | None) -> dict | None:
    if not isinstance(report, dict):
        return report

    normalized = copy.deepcopy(report)
    status = normalized.get("status")
    if status not in ("success", "partial", "failed"):
        normalized["status"] = "failed"
        status = "failed"

    if not normalized.get("is_web"):
        return normalized

    issues: list[str] = []
    if not normalized.get("web_started"):
        issues.append("Web 服务未成功启动或未验证")

    workflow = normalized.get("core_workflow")
    if not isinstance(workflow, dict):
        workflow = {}
    if workflow.get("verified") is not True:
        issues.append("未完成核心业务闭环验证")
    mode = str(workflow.get("mode") or "").strip().lower()
    if mode != "real":
        issues.append("核心功能未使用真实模式验证")
    if not workflow.get("steps"):
        issues.append("核心业务闭环缺少实测步骤")
    if not workflow.get("evidence"):
        issues.append("核心业务闭环缺少真实结果证据")
    if not str(workflow.get("result") or "").strip():
        issues.append("核心业务闭环缺少结果说明")

    if issues and status == "success":
        normalized["status"] = "failed" if not normalized.get("web_started") else "partial"

    if issues:
        existing_issues = normalized.get("acceptance_issues")
        if not isinstance(existing_issues, list):
            existing_issues = []
        normalized["acceptance_issues"] = list(dict.fromkeys([*existing_issues, *issues]))
        blockers = normalized.get("blockers")
        if not isinstance(blockers, list):
            blockers = []
        normalized["blockers"] = list(dict.fromkeys([*blockers, *[f"自动验收: {issue}" for issue in issues]]))

    return normalized


def task_status_from_report(report: dict | None, fallback: str = "failed") -> str:
    normalized = enforce_report_acceptance(report)
    if isinstance(normalized, dict) and normalized.get("status") in ("success", "partial", "failed"):
        return normalized["status"]
    return fallback


def extract_report(full_output: str) -> dict | None:
    """从 agent 完整输出里提取结构化复现报告（JSON）。
    容错:标记找不到/JSON 解析失败都返回 None（降级用日志）。"""
    if not full_output:
        return None
    start_mark = "===REPRO_REPORT_START==="
    end_mark = "===REPRO_REPORT_END==="
    try:
        si = full_output.rfind(start_mark)
        ei = full_output.rfind(end_mark)
        if si == -1 or ei == -1 or ei <= si:
            return _try_loose_json(full_output)
        chunk = full_output[si + len(start_mark):ei].strip()
        return _parse_report_json(chunk)
    except Exception:
        return None


def _parse_report_json(chunk: str) -> dict | None:
    """解析报告 JSON，带几种容错。"""
    chunk = chunk.strip()
    if chunk.startswith("```"):
        chunk = chunk.split("\n", 1)[-1] if "\n" in chunk else chunk
        if chunk.endswith("```"):
            chunk = chunk[:-3]
        chunk = chunk.strip()
        if chunk.startswith("json"):
            chunk = chunk[4:].strip()
    try:
        data = json.loads(chunk)
        return data if isinstance(data, dict) else None
    except Exception:
        try:
            a = chunk.find("{")
            b = chunk.rfind("}")
            if a != -1 and b > a:
                return json.loads(chunk[a:b + 1])
        except Exception:
            pass
    return None


def _try_loose_json(text: str) -> dict | None:
    """没标记时，尝试从尾部找一段像报告的 JSON（含 status/summary 字段）。"""
    idx = len(text)
    while True:
        b = text.rfind("}", 0, idx)
        if b == -1:
            return None
        a = text.rfind("{", 0, b)
        while a != -1:
            try:
                cand = json.loads(text[a:b + 1])
                if isinstance(cand, dict) and ("status" in cand or "summary" in cand):
                    return cand
            except Exception:
                pass
            a = text.rfind("{", 0, a)
        idx = b
    return None


def classify_log_line(line: str) -> str:
    """根据 OpenCode 输出格式给行分类，大屏据此上色（7 类）。

    返回: tool|read|exec|ok|warn|error|text
    """
    s = line.lstrip()
    if s.startswith("✱") or s.startswith("•"):
        return "tool"
    if s.startswith("→") or s.startswith("[•]"):
        return "read"
    if s.startswith("$"):
        return "exec"
    if s.startswith(">"):
        return "tool"
    if s.startswith("✓") or s.startswith("[✓]"):
        return "ok"
    if s.startswith("!"):
        return "warn"
    low = s.lower()
    if s.startswith(("✗", "X ", "Error", "ERROR", "EACCES", "Internal Error", "Traceback")) \
       or low.startswith("npm error") or low.startswith("error") \
       or "failed" in s or "SchemaError" in s or "permission denied" in s:
        return "error"
    if s.startswith("#") or s.startswith("["):
        return "tool"
    return "text"

