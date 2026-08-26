from __future__ import annotations

import re
from typing import Any

from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.router import LLMRouter

REAL_CWE = re.compile(r"^CWE-\d+$")

PATTERN_SYNTHESIZE_PROMPT = """你是漏洞模式抽象专家。平台已通过深度评审确认了一批同一漏洞类型（CWE）的漏洞知识条目，每条来自真实漏洞/攻击事件。请把它们的共性抽象、泛化成一个“漏洞模式”。

目标：让安全工程师或大模型看到这个模式后，能：(1) 识别同类漏洞；(2) 理解为什么这类漏洞普遍存在；(3) 知道怎么发现、怎么修。

要求：
- 只基于输入证据归纳，不要编造；输入未覆盖的字段标注“待补充”。
- 代表案例只从输入中选择，knowledge_id 必须来自输入。
- pattern_name 要具体到机制层面（如“Linux 内核 eBPF 验证器绕过导致越界访问”），不要只写“use-after-free”。

请以 JSON 返回：
{
  "pattern_name": "模式名(中文)",
  "pattern_summary": "2-4 句模式总览",
  "abstract_root_cause": "共性根因抽象：为什么这类漏洞普遍存在（机制层面，跨具体产品的归纳）",
  "common_trigger": "共性触发条件/前置条件",
  "common_exploit_primitives": ["共性利用原语"],
  "detection_guidance": "检测/排查思路（静态分析/动态调试/审计关注点）",
  "fix_paradigm": "修复范式（通用修复模式，不绑定具体产品）",
  "code_search_keywords": ["代码搜索关键词"],
  "representative_examples": [{"knowledge_id": 数字, "title": "一句话说明该案例体现的模式"}],
  "confidence": 0.0-1.0,
  "coverage_note": "说明本模式基于几条条目归纳、哪些维度证据薄弱"
}"""


def cluster_knowledge_by_cwe(knowledge_items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """按主 CWE 聚类漏洞知识。仅保留含真实 CWE(如 CWE-416) 的条目，无真实 CWE 的不建模式。

    排序优先：已确认/字段已接受 > 评分高，保证合成时代表案例质量。
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for item in knowledge_items:
        payload = item.get("payload") or {}
        cwes = [str(c) for c in (payload.get("cwe_ids") or []) if REAL_CWE.match(str(c))]
        if not cwes:
            continue
        primary = sorted(cwes)[0]
        groups.setdefault(primary, []).append(item)
    clusters: list[dict[str, Any]] = []
    for primary, members in groups.items():
        members.sort(
            key=lambda it: (str((it.get("payload") or {}).get("status") or "") == "confirmed", _field_acceptance(it), float(it.get("score") or 0)),
            reverse=True,
        )
        clusters.append({"cluster_key": f"cwe:{primary}", "cwe_ids": [primary], "members": members})
    clusters.sort(key=lambda cluster: len(cluster["members"]), reverse=True)
    return clusters


def _field_acceptance(item: dict[str, Any]) -> int:
    reviews = (item.get("payload") or {}).get("field_reviews") or {}
    return sum(1 for review in reviews.values() if review.get("status") in {"accepted", "modified"})


def synthesize_pattern(cluster: dict[str, Any], *, use_model: bool = True) -> dict[str, Any]:
    """跨素材生成单个漏洞模式。优先 LLM，失败/离线回退本地确定性归纳。"""
    members = cluster["members"]
    digest = _cluster_digest(members)
    payload = {"cluster_key": cluster["cluster_key"], "cwe_ids": cluster["cwe_ids"], "member_count": len(members), "knowledge_items": digest}
    if use_model:
        try:
            provider = LLMRouter().provider_for("vulnerability_pattern_synthesizer")
            if not isinstance(provider, LocalRuleProvider):
                response = provider.complete_json(prompt=PATTERN_SYNTHESIZE_PROMPT, payload=payload)
                result = response.get("result") or response.get("parsed") or {}
                if isinstance(result, dict) and result:
                    return {"provider": response.get("provider"), "status": "success", "model": response.get("model"), "result": {**result, "model_used": True}}
        except Exception as exc:  # pragma: no cover - external model dependent
            return {"provider": "local_rules", "status": "fallback", "result": {**_rule_pattern(cluster), "model_used": False, "llm_error": str(exc)[:300]}}
    return {"provider": "local_rules", "status": "fallback", "result": {**_rule_pattern(cluster), "model_used": False}}


def _cluster_digest(members: list[dict[str, Any]], *, limit: int = 10, max_chars: int = 20000) -> str:
    """把每条知识条目压成紧凑摘要，供 LLM 跨素材归纳。"""
    parts: list[str] = []
    for item in members[:limit]:
        p = item.get("payload") or {}
        lines = [
            f"条目 #{item.get('id')}（状态：{item.get('status')}，评分：{item.get('score')}）",
            f"- 标题：{item.get('title')}",
            f"- 漏洞类型：{p.get('vulnerability_type')}",
            f"- CVE：{', '.join(str(c) for c in (p.get('cve_ids') or []))}",
            f"- 根因：{p.get('root_cause_pattern')}",
            f"- 触发条件：{p.get('trigger_condition')}",
            f"- 攻击入口：{p.get('attack_entry')}",
            f"- 利用原语：{', '.join(str(x) for x in (p.get('exploit_primitives') or []))}",
            f"- 修复/缓解：{p.get('mitigation_or_fix')}",
            f"- 搜索关键词：{', '.join(str(x) for x in (p.get('code_search_keywords') or []))}",
        ]
        parts.append("\n".join(line for line in lines if line and not line.endswith(("：", ":"))))
    joined = "\n\n".join(parts)
    return joined[:max_chars]


def _rule_pattern(cluster: dict[str, Any]) -> dict[str, Any]:
    """无 LLM 时的确定性归纳：聚合簇内条目字段，作为可读的兜底模式。"""
    members = cluster["members"]
    payloads = [m.get("payload") or {} for m in members]
    cwes = cluster["cwe_ids"]
    types = sorted({str(p.get("vulnerability_type") or "") for p in payloads if p.get("vulnerability_type")})
    roots = _dedup(str(p.get("root_cause_pattern") or "") for p in payloads if p.get("root_cause_pattern"))
    triggers = _dedup(str(p.get("trigger_condition") or "") for p in payloads if p.get("trigger_condition"))
    fixes = _dedup(str(p.get("mitigation_or_fix") or "") for p in payloads if p.get("mitigation_or_fix"))
    primitives = _dedup(str(x) for p in payloads for x in (p.get("exploit_primitives") or []) if x)
    keywords = _dedup(str(x) for p in payloads for x in (p.get("code_search_keywords") or []) if x)
    return {
        "pattern_name": f"{cwes[0]} 类漏洞模式" + (f"（{'/'.join(types[:3])}）" if types else ""),
        "pattern_summary": f"基于 {len(members)} 条漏洞知识条目抽象出的 {cwes[0]} 类漏洞通用模式（本地规则归纳）。",
        "abstract_root_cause": "；".join(roots[:3]) or "待补充",
        "common_trigger": "；".join(triggers[:3]) or "待补充",
        "common_exploit_primitives": primitives[:8] or ["待补充"],
        "detection_guidance": "按上述共性触发条件与利用原语审计相关代码路径，重点核查根因抽象中列出的高危操作点。",
        "fix_paradigm": "；".join(fixes[:3]) or "待补充",
        "code_search_keywords": keywords[:10] or [],
        "representative_examples": [{"knowledge_id": m.get("id"), "title": str(m.get("title") or "")[:120]} for m in members[:5]],
        "confidence": round(min(0.9, 0.35 + 0.08 * len(members)), 2),
        "coverage_note": f"本模式基于 {len(members)} 条漏洞知识条目归纳（本地规则回退）。",
    }


def _dedup(values: Any) -> list[str]:
    seen: list[str] = []
    for value in values:
        value = str(value).strip()
        if value and value not in seen:
            seen.append(value)
    return seen


def build_pattern_payload(cluster: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
    members = cluster["members"]
    result = output.get("result") if isinstance(output.get("result"), dict) else output
    return {
        "pattern_id": f"ptn-{cluster['cluster_key'].replace(':', '-')}",
        "cluster_key": cluster["cluster_key"],
        "cwe_ids": cluster["cwe_ids"],
        "member_count": len(members),
        "knowledge_ids": [int(m.get("id")) for m in members if m.get("id") is not None],
        "pattern_name": result.get("pattern_name") or f"{cluster['cwe_ids'][0]} 类漏洞模式",
        "pattern_summary": result.get("pattern_summary") or "",
        "abstract_root_cause": result.get("abstract_root_cause") or "",
        "common_trigger": result.get("common_trigger") or "",
        "common_exploit_primitives": list(result.get("common_exploit_primitives") or []) or [],
        "detection_guidance": result.get("detection_guidance") or "",
        "fix_paradigm": result.get("fix_paradigm") or "",
        "code_search_keywords": list(result.get("code_search_keywords") or []) or [],
        "representative_examples": list(result.get("representative_examples") or []) or [],
        "coverage_note": result.get("coverage_note") or "",
        "confidence": _safe_float(result.get("confidence"), 0.5),
        "generated_by": "pattern_synthesizer",
        "model_used": bool(result.get("model_used", False)),
        "model_output": output,
    }


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback


def render_pattern_markdown(item: dict[str, Any]) -> str:
    """把漏洞模式条目渲染成可下载的 markdown 文档。"""
    payload = item.get("payload") or {}
    cwes = ", ".join(str(c) for c in (payload.get("cwe_ids") or []))
    lines = [
        f"# 漏洞模式：{payload.get('pattern_name') or item.get('title') or '未命名模式'}",
        "",
        f"> 模式 ID：{payload.get('pattern_id') or item.get('id')} · 覆盖 {payload.get('member_count')} 条漏洞知识",
        "",
        "## 模式总览",
        "",
        payload.get("pattern_summary") or "暂无",
        "",
        "## 基本信息",
        "",
        f"- CWE：{cwes or '无'}",
        f"- 置信度：{_percent(payload.get('confidence'))}",
        f"- 生成方式：{'大模型抽象' if payload.get('model_used') else '本地规则归纳'}",
        "",
        "## 共性根因抽象",
        "",
        payload.get("abstract_root_cause") or "待补充",
        "",
        "## 共性触发条件",
        "",
        payload.get("common_trigger") or "待补充",
        "",
        "## 共性利用原语",
        "",
    ]
    primitives = payload.get("common_exploit_primitives") or []
    if primitives:
        lines.extend(f"- {p}" for p in primitives)
    else:
        lines.append("- 待补充")
    lines.extend([
        "",
        "## 检测思路",
        "",
        payload.get("detection_guidance") or "待补充",
        "",
        "## 修复范式",
        "",
        payload.get("fix_paradigm") or "待补充",
        "",
        "## 代码搜索关键词",
        "",
    ])
    keywords = payload.get("code_search_keywords") or []
    if keywords:
        lines.extend(f"- `{k}`" for k in keywords)
    else:
        lines.append("- 无")
    lines.extend(["", "## 代表案例", ""])
    examples = payload.get("representative_examples") or []
    for example in examples:
        if isinstance(example, dict):
            lines.append(f"- 知识#{example.get('knowledge_id')}：{example.get('title')}")
    if not examples:
        lines.append("- 无")
    lines.extend(["", f"*{payload.get('coverage_note') or ''}*"])
    return "\n".join(lines)


def _percent(value: Any) -> str:
    try:
        return f"{float(value) * 100:.0f}%"
    except (TypeError, ValueError):
        return "-"
