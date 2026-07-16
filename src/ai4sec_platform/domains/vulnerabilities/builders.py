from __future__ import annotations

import sqlite3

from ai4sec_platform.db import repositories as repo


def build_material(item: dict) -> dict:
    return {"item_type": "material", "title": item.get("title", "未命名漏洞素材"), "payload": item}


def build_vulnerability_items(conn: sqlite3.Connection, items: list[dict], *, run_id: str) -> dict[str, int]:
    materials = 0
    knowledge_candidates = 0
    for item in items:
        payload = repo.loads(item.get("normalized_json"), {}) if "normalized_json" in item else item
        item_id = repo.create_domain_item(
            conn,
            domain="vulnerabilities",
            item_type="material",
            title=payload.get("title") or "未命名漏洞素材",
            summary=payload.get("summary") or "来自漏洞素材 raw pipeline，待知识提取。",
            score=_safe_float(payload.get("confidence")),
            status="待知识提取" if payload.get("is_relevant") else "待复核",
            source="raw_pipeline",
            source_url=payload.get("url") or "",
            primary_date=payload.get("primary_date") or "",
            tags=["raw_pipeline", payload.get("category") or "素材"],
            metrics={"pipeline_run": run_id, "confidence": payload.get("confidence"), "markdown_length": payload.get("markdown_length")},
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
            confidence=_safe_float(payload.get("confidence")),
            payload={"run_id": run_id, "item_key": payload.get("item_key")},
        )
        if payload.get("is_relevant") or (_safe_float(payload.get("confidence")) or 0) >= 0.7:
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
