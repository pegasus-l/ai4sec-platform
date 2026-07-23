from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.vulnerabilities.entity_normalizers import enrich_material_entities, material_text
from ai4sec_platform.domains.vulnerabilities.evidence_extractors import extract_material_evidence
from ai4sec_platform.domains.vulnerabilities.material_classifiers import classify_material
from ai4sec_platform.domains.vulnerabilities.relevance_scorers import score_material


def review_crawled_material(page: dict[str, Any], *, requirements: str = "", confidence_threshold: float = 0.55) -> dict[str, Any]:
    """Deterministic review that mirrors the old AI checker schema.

    The old project used an LLM to decide whether a crawled page was a high-quality
    vulnerability material. This local reviewer keeps the same output contract while
    avoiding online model calls; it can be replaced by an LLMProvider later.
    """
    if not page.get("success"):
        return _review(page, is_relevant=False, confidence=0.0, decision="reject", reason=f"抓取失败：{page.get('error') or 'unknown'}", key_findings=[])

    normalized = _normalize_review_input(page)
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

    decision = "accept" if confidence >= confidence_threshold and scoring.priority in {"high", "medium"} else "needs_review" if confidence >= 0.35 else "reject"
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
        extra={"classification": classification, "scoring": scoring.as_payload(), "extracted_evidence": evidence, "reviewer": "local_rules", "model_used": False},
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
