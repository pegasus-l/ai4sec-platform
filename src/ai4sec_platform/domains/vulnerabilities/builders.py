from __future__ import annotations

import sqlite3

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.vulnerabilities.entity_normalizers import enrich_material_entities
from ai4sec_platform.domains.vulnerabilities.evidence_extractors import extract_material_evidence
from ai4sec_platform.domains.vulnerabilities.material_classifiers import classify_material
from ai4sec_platform.domains.vulnerabilities.relevance_scorers import score_material


def build_material(item: dict) -> dict:
    return {"item_type": "material", "title": item.get("title", "未命名漏洞素材"), "payload": item}


def build_vulnerability_items(conn: sqlite3.Connection, items: list[dict], *, run_id: str) -> dict[str, int]:
    materials = 0
    knowledge_candidates = 0
    for item in items:
        payload = repo.loads(item.get("normalized_json"), {}) if "normalized_json" in item else item
        payload = enrich_material_entities(payload)
        classification = classify_material(payload)
        extracted = extract_material_evidence(payload)
        scoring = score_material({**payload, "classification": classification.as_payload()})
        material_type = _material_type(classification.category)
        payload = {**payload, "material_type": material_type, "classification": classification.as_payload(), "scoring": scoring.as_payload(), "extracted_evidence": extracted}
        item_id = repo.create_domain_item(
            conn,
            domain="vulnerabilities",
            item_type="material",
            title=payload.get("title") or "未命名漏洞素材",
            summary=payload.get("summary") or "来自漏洞素材 raw pipeline，待知识提取。",
            score=scoring.score,
            status="待知识提取" if scoring.priority in {"high", "medium"} or payload.get("is_relevant") else "低相关待复核",
            source="raw_pipeline",
            source_url=payload.get("url") or "",
            primary_date=payload.get("primary_date") or "",
            tags=["raw_pipeline", material_type, payload.get("category") or "素材", classification.category, scoring.grade, *payload.get("cve_ids", [])[:3]],
            metrics={"pipeline_run": run_id, "confidence": payload.get("confidence"), "markdown_length": payload.get("markdown_length"), "score_breakdown": scoring.breakdown, "cve_count": len(payload.get("cve_ids", [])), "snippet_count": len(extracted.get("evidence_snippets", []))},
            payload=payload,
        )
        materials += 1
        content = payload.get("summary") or "\n".join(str(x) for x in payload.get("key_findings") or [])
        repo.create_evidence(
            conn,
            domain="vulnerabilities",
            domain_item_id=item_id,
            evidence_type="material_relevance",
            title="漏洞素材相关性证据",
            content=content,
            source_url=payload.get("url") or "",
            confidence=min(1.0, scoring.score / 100),
            payload={"run_id": run_id, "item_key": payload.get("item_key"), "classification": classification.as_payload(), "scoring": scoring.as_payload(), "extracted_evidence": extracted},
        )
        for snippet in extracted.get("evidence_snippets", []):
            repo.create_evidence(
                conn,
                domain="vulnerabilities",
                domain_item_id=item_id,
                evidence_type=f"material_{snippet.get('snippet_type') or 'snippet'}",
                title=snippet.get("title") or "漏洞素材证据片段",
                content=snippet.get("content") or "",
                source_url=snippet.get("source_url") or payload.get("url") or "",
                confidence=snippet.get("confidence"),
                payload={"run_id": run_id, "item_key": payload.get("item_key"), **snippet},
            )
        if scoring.score >= 45 or payload.get("is_relevant") or (_safe_float(payload.get("confidence")) or 0) >= 0.7:
            knowledge_candidates += 1
            repo.create_human_queue_item(
                conn,
                domain="vulnerabilities",
                item_id=item_id,
                queue_type="knowledge_extraction",
                priority=2,
                reason="Raw pipeline 识别到高相关漏洞素材，等待知识提取。",
                payload={"run_id": run_id, "item_key": payload.get("item_key")},
            )
    return {"materials": materials, "knowledge_candidates": knowledge_candidates}


def _safe_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _material_type(category: str) -> str:
    mapping = {
        "PoC/Exploit": "poc_exploit",
        "深度技术分析": "tech_analysis",
        "漏洞公告": "advisory",
        "影响范围线索": "affected_version",
    }
    return mapping.get(category, "unknown")
