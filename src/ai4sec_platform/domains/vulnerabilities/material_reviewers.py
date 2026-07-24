from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.vulnerabilities.entity_normalizers import enrich_material_entities, material_text
from ai4sec_platform.domains.vulnerabilities.evidence_extractors import extract_material_evidence
from ai4sec_platform.domains.vulnerabilities.material_classifiers import classify_material
from ai4sec_platform.domains.vulnerabilities.relevance_scorers import score_material
from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.router import LLMRouter

MATERIAL_REVIEW_PROMPT = """你是一个资深安全研究员和技术内容审核专家。请判断网页是否值得作为“优质漏洞知识素材”展示和沉淀。
请优先保留高质量漏洞技术分析、可复现 PoC/Exploit、带完整根因/触发条件/利用链/修复分析的研究文章。
审核标准：
- 技术深度：包含具体代码片段、真实 payload、调用链/数据流、漏洞根因、修复前后对比或原理说明。
- 方法论价值：描述发现路径、复现步骤、调试/分析工具链、绕过或防护机制突破。
- 利用分析：说明利用原语、能力边界、利用链构建、稳定性或限制条件。
排除项：
- 仅以 CVE/NVD/OpenCVE 编号页、厂商公告、补丁列表、新闻、营销、百科介绍为主线，缺少独立技术分析的内容，不应 accept；最多 needs_review 或 reject。
- CVE 编号只能作为聚合连接键，不能单独作为优质素材通过依据。
请以 JSON 返回：
{
  "is_relevant": true/false,
  "decision": "accept|needs_review|reject",
  "confidence": 0.0-1.0,
  "reason": "简短审核理由",
  "key_findings": ["发现1"],
  "material_type": "poc_exploit|tech_analysis|advisory|patch|discussion|other",
  "quality_signals": ["code", "payload", "root_cause", "exploit_chain", "repro_steps", "fix_analysis", "methodology"],
  "cve_ids": ["CVE-YYYY-NNNN"],
  "cwe_ids": ["CWE-NNN"],
  "affected_products": ["产品或组件"],
  "evidence_snippets": [{"snippet_type":"root_cause|trigger|poc|patch|summary", "content":"证据片段"}]
}。"""


def review_crawled_material(page: dict[str, Any], *, requirements: str = "", confidence_threshold: float = 0.55) -> dict[str, Any]:
    """Deterministic review that mirrors the old AI checker schema.

    The old project used an LLM to decide whether a crawled page was a high-quality
    vulnerability material. This reviewer keeps the same output contract and uses
    an OpenAI-compatible model when configured, with local rules as fallback.
    """
    if not page.get("success"):
        return _review(page, is_relevant=False, confidence=0.0, decision="reject", reason=f"抓取失败：{page.get('error') or 'unknown'}", key_findings=[])

    normalized = _normalize_review_input(page)
    llm_review = _try_llm_review(normalized, requirements=requirements, confidence_threshold=confidence_threshold)
    if llm_review:
        return llm_review
    return _rule_review(normalized, requirements=requirements, confidence_threshold=confidence_threshold)


def _try_llm_review(normalized: dict[str, Any], *, requirements: str, confidence_threshold: float) -> dict[str, Any] | None:
    try:
        provider = LLMRouter().provider_for("vulnerability_material_reviewer")
        if isinstance(provider, LocalRuleProvider):
            return None
        payload = {"url": normalized.get("url"), "title": normalized.get("title"), "requirements": requirements, "content": str(normalized.get("cleaned_text") or normalized.get("summary") or "")[:24000]}
        response = provider.complete_json(prompt=MATERIAL_REVIEW_PROMPT, payload=payload)
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
            {**normalized, "material_type": result.get("material_type") or normalized.get("material_type"), "cve_ids": extra_evidence["cve_ids"], "cwe_ids": extra_evidence["cwe_ids"], "affected_products": extra_evidence["affected_products"]},
            is_relevant=decision in {"accept", "needs_review"},
            confidence=round(confidence, 2),
            decision=decision,
            reason=str(result.get("reason") or "模型完成漏洞素材审核。"),
            key_findings=_list_str(result.get("key_findings")),
            extra={"classification": {"category": result.get("material_type") or "llm_review", "confidence": confidence}, "scoring": {"score": round(confidence * 100, 2), "priority": "high" if decision == "accept" else "medium" if decision == "needs_review" else "low"}, "extracted_evidence": extra_evidence, "reviewer": response.get("provider"), "review_model": response.get("model"), "model_used": True, "prompt": MATERIAL_REVIEW_PROMPT, "llm_output": result, "quality_gate": _quality_gate_reason(result, decision)},
        )
    except Exception as exc:  # pragma: no cover - external model dependent
        normalized["llm_review_error"] = str(exc)[:300]
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
        extra={"classification": classification, "scoring": scoring.as_payload(), "extracted_evidence": evidence, "reviewer": "local_rules", "model_used": False, "llm_review_error": normalized.get("llm_review_error")},
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
    has_deep_signal = bool(quality & {"code", "payload", "root_cause", "exploit_chain", "repro_steps", "fix_analysis", "methodology"})
    has_deep_evidence = any(str(item.get("snippet_type", "")).lower() in {"root_cause", "trigger", "poc", "patch"} for item in evidence if isinstance(item, dict))
    if material_type in {"advisory", "patch", "other"} and not (has_deep_signal or has_deep_evidence):
        return "needs_review"
    if not (has_deep_signal or has_deep_evidence or material_type in {"poc_exploit", "tech_analysis"}):
        return "needs_review"
    return decision


def _quality_gate_reason(result: dict[str, Any], decision: str) -> str:
    if decision == "accept":
        return "passed_quality_gate"
    return "not_accepted_without_deep_technical_evidence"


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
