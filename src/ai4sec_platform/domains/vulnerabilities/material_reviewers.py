from __future__ import annotations

import re
import time
from typing import Any

from ai4sec_platform.domains.vulnerabilities.model_inputs import prepare_model_input
from ai4sec_platform.domains.vulnerabilities.entity_normalizers import enrich_material_entities, material_text
from ai4sec_platform.domains.vulnerabilities.evidence_extractors import extract_material_evidence
from ai4sec_platform.domains.vulnerabilities.material_classifiers import classify_material
from ai4sec_platform.domains.vulnerabilities.relevance_scorers import score_material
from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.router import LLMRouter

MATERIAL_REVIEW_PROMPT = """你是一个资深安全研究员和技术内容审核专家。请分析用户消息 JSON 中 content 字段提供的网页正文内容，判断是否属于“高质量漏洞技术分析文章（writeup）”。

本平台的目标：收集能讲清某个漏洞“前因后果”的优质 writeup 素材，让大模型只看素材就能完整理解该漏洞，并据此抽象漏洞模式。因此审核时，除技术深度外，重点评估素材对“前因后果故事链路”的完整交代。

检查要求：
  同时满足基础要求和评估标准

  基础要求：
    {requirements}
    - 首选：安全社区/技术平台发布的深度漏洞分析文章（writeup），能讲清 背景/影响→根因→触发→利用→修复 中的核心链路。
    - 次选：漏洞利用代码仓库/Exploit 数据库、学术/工业顶会文章、内核安全学习资源——仅当其内容本身就是完整技术分析（而非只有代码/幻灯片/链接列表）时接受。
    - 必须为原创内容非转载。

  评估标准：
    完整性与教学性（权重 30%）
    - [ ] 前因后果自包含：覆盖 根因→触发→利用→修复 中的核心链路，缺链不影响“看懂这个漏洞”
    - [ ] 不依赖外部前置知识，新读者能独立理解
    - [ ] 结构清晰，有步骤/层级/结论，可直接作为 LLM 知识来源
    - [ ] 关键结论都有推导支撑，而非只给结论

    技术深度（权重 30%）
    - [ ] 包含具体代码片段（非伪代码，可验证）
    - [ ] 展示完整调用链或数据流
    - [ ] 解释漏洞根因（为什么错，而非哪里错）
    - [ ] 有修复前后代码对比或原理说明

    方法论价值（权重 20%）
    - [ ] 描述发现路径（如何找到这个漏洞）
    - [ ] 提供可复现的步骤或环境配置
    - [ ] 分析工具链使用或调试技巧
    - [ ] 讨论绕过技术或防护机制突破

    利用分析（权重 20%）
    - [ ] 说明利用原语和能力边界
    - [ ] 分析利用链构建逻辑
    - [ ] 讨论利用稳定性/限制条件
    - [ ] 不是单纯说“可导致 RCE”，而是解释如何导致

    排除项（出现任意一项直接判定为不合格）
    - [ ] 以 CVE 编号或厂商公告为主线
    - [ ] 新闻体（“某公司发布补丁修复某漏洞”）
    - [ ] 营销体（“某产品采用先进技术保障安全”）
    - [ ] AI 摘要体（泛泛而谈，无代码，无细节）
    - [ ] 仅复述官方公告，无独立分析
    - [ ] 无技术细节的威胁恐吓文
    - [ ] 链接索引/资源导航页：内容主体是外部链接列表或 CVE 编号集合（如 awesome-list、resource collection），无具体漏洞技术分析、无代码、无利用细节
    - [ ] GitHub 仓库页面本身：内容含 GitHub 导航菜单/侧边栏/UI 元素，而非 README 正文的技术分析内容（仓库内独立的漏洞 writeup 文档除外）
    - [ ] 视频/演讲页面：内容为视频、幻灯片或演讲简介，正文无可读技术分析文本
    - [ ] 只有代码没有讲解：纯 PoC/exploit 代码或提交 diff，无文字解释

请只返回 JSON，保持以下 schema；其中扩展字段用于新平台事件聚合和证据追溯，但不能降低上述审核标准：
{{
  "is_relevant": true,
  "decision": "accept|needs_review|reject",
  "confidence": 0.0,
  "reason": "判断理由的简要说明",
  "title_cn": "标题的简洁中文翻译(意译即可, 技术术语保持准确, 如 'Linux 内核 kSmbd 未授权栈溢出利用')",
  "key_findings": ["关键发现1", "关键发现2"],
  "material_type": "poc_exploit|tech_analysis|kernel_security|academic_conf|reference_index|other",
  "quality_signals": ["code", "call_chain", "data_flow", "root_cause", "fix_analysis", "discovery_method", "repro_steps", "tooling", "bypass", "exploit_primitive", "exploit_chain", "stability_limit"],
  "cve_ids": ["CVE-YYYY-NNNN"],
  "cwe_ids": ["CWE-NNN"],
  "affected_products": ["产品或组件"],
  "evidence_snippets": [{{"snippet_type":"root_cause|trigger|poc|patch|summary", "content":"证据片段"}}]
}}"""


def review_crawled_material(page: dict[str, Any], *, requirements: str = "", confidence_threshold: float = 0.55, use_model: bool = True, fallback_mode: str = "needs_review", llm_max_attempts: int = 2) -> dict[str, Any]:
    """Deterministic review that mirrors the old AI checker schema.

    The old project used an LLM to decide whether a crawled page was a high-quality
    vulnerability material. This reviewer keeps the same output contract and uses
    an OpenAI-compatible model when configured.

    LLM 失败时的处理由 fallback_mode 决定(默认 `needs_review` = 诚实标记, 不做规则决策):
      - "needs_review": LLM 有界重试(llm_max_attempts)后仍失败 → failed_review 标记(decision=needs_review, reviewer=llm_failed)。
      - "retry": 同 needs_review, 但默认多试几次(≥3)。
      - "rules": 旧行为, 显式 opt-in —— LLM 失败回退本地规则做 accept/reject 决策。
    """
    if not page.get("success"):
        return _review(page, is_relevant=False, confidence=0.0, decision="reject", reason=f"抓取失败：{page.get('error') or 'unknown'}", key_findings=[])

    normalized = _normalize_review_input(page)
    if len(str(normalized.get("cleaned_text") or "").strip()) < 800:
        if re.search(r"\bCVE-\d{4}-\d{4,}\b", f"{normalized.get('title', '')}\n{normalized.get('cleaned_text', '')}", re.IGNORECASE):
            return _review(
                normalized,
                is_relevant=True,
                confidence=0.2,
                decision="needs_review",
                reason="正文内容不足 800 字符；CVE 页面仅保留为事件聚合线索，不能作为优质技术素材。",
                key_findings=[],
            )
        return _review(
            normalized,
            is_relevant=False,
            confidence=0.0,
            decision="reject",
            reason="正文内容不足 800 字符，不能作为高质量漏洞技术分析素材。",
            key_findings=[],
        )
    if fallback_mode not in {"needs_review", "retry", "rules"}:
        fallback_mode = "needs_review"
    max_attempts = max(int(llm_max_attempts), 1)
    if fallback_mode == "retry":
        max_attempts = max(max_attempts, 3)
    llm_review = _try_llm_review(normalized, requirements=requirements, confidence_threshold=confidence_threshold, max_attempts=max_attempts) if use_model else None
    if llm_review:
        return llm_review
    if fallback_mode == "rules":
        return _rule_review(normalized, requirements=requirements, confidence_threshold=confidence_threshold)
    error = str(normalized.get("llm_review_error") or "模型审核不可用或已禁用")
    return failed_review(normalized, error=error)


def failed_review(page: dict[str, Any], *, error: str) -> dict[str, Any]:
    """LLM 审核失败/超时的诚实标记: 不产出 accept/reject 决策, 留给人工复核。

    与 _rule_review 的关键区别: 规则至多作为 evidence 注解(不在此实现), 决策字段
    固定 needs_review + reviewer=llm_failed, llm_error 置顶层(供 is_failure/审计识别)。
    needs_review 且 BuildAcceptedVulnerabilityMaterialsStep 默认 include_needs_review=False
    → 不进入素材构建, 只留 review 阶段行给人审。
    """
    normalized = _normalize_review_input(page)
    normalized["llm_review_error"] = error[:300]
    return _review(
        normalized,
        is_relevant=True,
        confidence=0.0,
        decision="needs_review",
        reason=f"LLM 审核失败，标记待人工复核：{error}",
        key_findings=[],
        extra={
            "reviewer": "llm_failed",
            "model_used": False,
            "llm_error": error[:300],
            "fallback_mode": "needs_review",
            "latency_ms": normalized.get("llm_review_latency_ms", 0),
        },
    )


def _try_llm_review(normalized: dict[str, Any], *, requirements: str, confidence_threshold: float, max_attempts: int = 2, backoff_seconds: float = 2.0) -> dict[str, Any] | None:
    """有界重试的 LLM 审核。全部尝试失败 → 置 llm_review_error 并返回 None(由调用方按 fallback_mode 处理)。"""
    started = time.perf_counter()
    last_error = ""
    for attempt in range(1, max_attempts + 1):
        try:
            provider = LLMRouter().provider_for("vulnerability_material_reviewer")
            if isinstance(provider, LocalRuleProvider):
                return None
            content, input_truncated = prepare_model_input(str(normalized.get("cleaned_text") or normalized.get("summary") or ""), profile="vulnerability_material_reviewer")
            payload = {"url": normalized.get("url"), "title": normalized.get("title"), "requirements": requirements, "content": content}
            prompt = MATERIAL_REVIEW_PROMPT.format(requirements=requirements or "- 无额外要求")
            response = provider.complete_json(prompt=prompt, payload=payload)
            result = response.get("result") or response.get("parsed") or {}
            confidence = _safe_float(result.get("confidence"), 0.0)
            decision = str(result.get("decision") or ("accept" if result.get("is_relevant") and confidence >= confidence_threshold else "needs_review" if result.get("is_relevant") else "reject"))
            if decision not in {"accept", "needs_review", "reject"}:
                decision = "needs_review"
            decision = _enforce_quality_gate(result, decision)
            extra_evidence = {
                "cve_ids": _list_str(result.get("cve_ids")),
                "cwe_ids": _list_str(result.get("cwe_ids")),
                "affected_products": _list_str(result.get("affected_products")),
                "evidence_snippets": [item for item in result.get("evidence_snippets") or [] if isinstance(item, dict)],
            }
            return _review(
                {**normalized, "material_type": result.get("material_type") or normalized.get("material_type"), "title_cn": str(result.get("title_cn") or "").strip(), "cve_ids": extra_evidence["cve_ids"], "cwe_ids": extra_evidence["cwe_ids"], "affected_products": extra_evidence["affected_products"]},
                is_relevant=decision in {"accept", "needs_review"},
                confidence=round(confidence, 2),
                decision=decision,
                reason=str(result.get("reason") or "模型完成漏洞素材审核。"),
                key_findings=_list_str(result.get("key_findings")),
                extra={"classification": {"category": result.get("material_type") or "llm_review", "confidence": confidence}, "scoring": {"score": round(confidence * 100, 2), "priority": "high" if decision == "accept" else "medium" if decision == "needs_review" else "low"}, "extracted_evidence": extra_evidence, "reviewer": response.get("provider"), "review_model": response.get("model"), "model_used": True, "prompt": prompt, "llm_output": result, "quality_gate": _quality_gate_reason(result, decision), "model_input_characters": len(content), "model_input_truncated": input_truncated, "latency_ms": int((time.perf_counter() - started) * 1000)},
            )
        except Exception as exc:  # pragma: no cover - external model dependent
            last_error = str(exc)
            if attempt < max_attempts:
                time.sleep(backoff_seconds * attempt)
    normalized["llm_review_error"] = (last_error or "model error")[:300]
    normalized["llm_review_latency_ms"] = int((time.perf_counter() - started) * 1000)
    return None


def _rule_review(normalized: dict[str, Any], *, requirements: str, confidence_threshold: float) -> dict[str, Any]:
    enriched = enrich_material_entities(normalized)
    classification = classify_material(enriched).as_payload()
    evidence = extract_material_evidence({**enriched, "classification": classification})
    scoring = score_material({**enriched, "classification": classification, "extracted_evidence": evidence})
    confidence = min(0.99, max(float(classification.get("confidence") or 0.0), scoring.score / 100))
    if evidence.get("cve_ids"):
        confidence = min(0.99, confidence + 0.08)
    if evidence.get("has_poc"):
        confidence = min(0.99, confidence + 0.08)
    if normalized.get("markdown_length", 0) < 400:
        confidence = max(0.0, confidence - 0.18)

    decision = _rule_decision(classification, evidence, confidence=confidence, confidence_threshold=confidence_threshold, scoring_priority=scoring.priority)
    gate_result = _rule_gate_result(classification, evidence)
    if decision == "accept":
        decision = _enforce_quality_gate(gate_result, decision)
    reasons = list(classification.get("reasons") or []) + list(scoring.reasons or [])
    if requirements:
        reasons.append(f"审核要求：{requirements[:180]}")
    key_findings = _key_findings(evidence, reasons)
    return _review(
        normalized,
        is_relevant=decision in {"accept", "needs_review"},
        confidence=round(confidence, 2),
        decision=decision,
        reason="；".join(dict.fromkeys(reasons)) or "本地规则未发现足够高质量漏洞技术信号。",
        key_findings=key_findings,
        extra={"classification": classification, "scoring": scoring.as_payload(), "extracted_evidence": evidence, "reviewer": "local_rules", "model_used": False, "quality_gate": _quality_gate_reason(gate_result, decision), "llm_review_error": normalized.get("llm_review_error"), "latency_ms": normalized.get("llm_review_latency_ms", 0)},
    )


def _normalize_review_input(page: dict[str, Any]) -> dict[str, Any]:
    markdown = str(page.get("cleaned_text") or page.get("markdown") or page.get("content") or page.get("snippet") or "")
    return {
        **page,
        "url": page.get("url") or page.get("source_url") or "",
        "title": page.get("title") or page.get("url") or "未命名漏洞素材",
        "summary": page.get("summary") or page.get("snippet") or markdown[:500],
        "markdown_length": page.get("markdown_length") or len(markdown),
        "raw": {"crawl_info": page.get("crawl_info") or {}, "markdown": markdown, "candidate": page.get("raw") or page},
    }


def _review(page: dict[str, Any], *, is_relevant: bool, confidence: float, decision: str, reason: str, key_findings: list[str], extra: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        **page,
        "is_relevant": is_relevant,
        "confidence": confidence,
        "decision": decision,
        "reason": reason,
        "check_reason": reason,
        "key_findings": key_findings,
        "category": page.get("category") or decision,
        "review": {"is_relevant": is_relevant, "confidence": confidence, "decision": decision, "reason": reason, "key_findings": key_findings, **(extra or {})},
    }


def _key_findings(evidence: dict[str, Any], reasons: list[str]) -> list[str]:
    findings: list[str] = []
    for cve in evidence.get("cve_ids") or []:
        findings.append(f"命中 CVE：{cve}")
    for cwe in evidence.get("cwe_ids") or []:
        findings.append(f"命中 CWE：{cwe}")
    for product in evidence.get("affected_products") or []:
        findings.append(f"影响组件/产品：{product}")
    snippets = evidence.get("evidence_snippets") or []
    for snippet in snippets[:3]:
        content = str(snippet.get("content") or "").strip()
        if content:
            findings.append(content[:180])
    findings.extend(reason for reason in reasons[:3] if reason)
    return list(dict.fromkeys(findings))[:8]


def _list_str(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _enforce_quality_gate(result: dict[str, Any], decision: str) -> str:
    if decision != "accept":
        return decision
    quality = set(_list_str(result.get("quality_signals")))
    material_type = str(result.get("material_type") or "").lower()
    evidence = result.get("evidence_snippets") or []
    has_deep_signal = bool(quality & {"code", "payload", "call_chain", "data_flow", "root_cause", "exploit_chain", "exploit_primitive", "repro_steps", "fix_analysis", "discovery_method", "tooling", "bypass", "stability_limit", "methodology"})
    has_deep_evidence = any(str(item.get("snippet_type", "")).lower() in {"root_cause", "trigger", "poc", "patch"} for item in evidence if isinstance(item, dict))
    if material_type in {"advisory", "patch", "other"} and not (has_deep_signal or has_deep_evidence):
        return "needs_review"
    if not (has_deep_signal or has_deep_evidence or material_type in {"poc_exploit", "tech_analysis", "kernel_security", "academic_conf"}):
        return "needs_review"
    return decision


def _quality_gate_reason(result: dict[str, Any], decision: str) -> str:
    if decision == "accept":
        return "passed_quality_gate"
    return "not_accepted_without_deep_technical_evidence"


def _rule_gate_result(classification: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    """把规则路径的分类/证据结果映射为 _enforce_quality_gate 可消费的结构，统一两条评审路径的深度门禁。

    规则路径没有 LLM 的 quality_signals，这里按分类命中和证据片段类型重建等价信号：
    - 命中 PoC/Exploit 线索 → poc_exploit；命中技术分析线索 → tech_analysis；命中公告线索 → advisory；否则 other。
    - 证据片段类型 root_cause/trigger/poc/patch 分别映射到 root_cause/trigger/poc/fix_analysis 信号。
    """
    signals = classification.get("signals") or {}
    if signals.get("poc_hits"):
        material_type = "poc_exploit"
    elif signals.get("tech_hits"):
        material_type = "tech_analysis"
    elif signals.get("advisory_hits"):
        material_type = "advisory"
    else:
        material_type = "other"
    quality: set[str] = set()
    if signals.get("poc_hits"):
        quality.add("poc")
    if signals.get("tech_hits"):
        quality.add("tech")
    for snippet in evidence.get("evidence_snippets") or []:
        if not isinstance(snippet, dict):
            continue
        st = str(snippet.get("snippet_type") or "").lower()
        if st == "root_cause":
            quality.add("root_cause")
        elif st == "trigger":
            quality.add("trigger")
        elif st == "poc":
            quality.add("poc")
        elif st == "patch":
            quality.add("fix_analysis")
    return {
        "material_type": material_type,
        "quality_signals": sorted(quality),
        "evidence_snippets": evidence.get("evidence_snippets") or [],
    }


def _rule_decision(classification: dict[str, Any], evidence: dict[str, Any], *, confidence: float, confidence_threshold: float, scoring_priority: str) -> str:
    signals = classification.get("signals") or {}
    poc_hits = signals.get("poc_hits") or []
    tech_hits = signals.get("tech_hits") or []
    advisory_hits = signals.get("advisory_hits") or []
    snippets = evidence.get("evidence_snippets") or []
    has_deep_evidence = any(snippet.get("snippet_type") in {"root_cause", "trigger", "poc", "patch"} for snippet in snippets if isinstance(snippet, dict))
    if confidence >= confidence_threshold and scoring_priority in {"high", "medium"} and (poc_hits or tech_hits or has_deep_evidence):
        return "accept"
    if advisory_hits or evidence.get("cve_ids"):
        return "needs_review"
    if confidence >= 0.35:
        return "needs_review"
    return "reject"


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback
