from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.news import repository as news_repo
from ai4sec_platform.domains.news.classifiers import classify_news_item
from ai4sec_platform.domains.news.scorers import score_news_item


def build_news_items(conn: sqlite3.Connection, items: list[dict[str, Any]], *, run_id: str) -> dict[str, Any]:
    created = 0
    updated = 0
    item_ids: list[int] = []
    for payload in items:
        classification = classify_news_item(payload)
        scoring = score_news_item({**payload, "classification": classification.as_payload()})
        item_key = str(payload["item_key"])
        item_type = str(payload.get("source_type") or "article")
        technical_points = list(dict.fromkeys([*payload.get("topics", []), *classification.tags]))[:10]
        enriched = {
            **payload,
            "highlight": _highlight(payload.get("summary") or payload.get("title") or ""),
            "technical_points": technical_points,
            "classification": classification.as_payload(),
            "scoring": scoring.as_payload(),
            "pipeline_run": run_id,
        }
        tags = list(dict.fromkeys([item_type, classification.category, *classification.tags, *payload.get("topics", [])]))
        metrics = {"pipeline_run": run_id, "classification_confidence": classification.confidence, "score_breakdown": scoring.breakdown}
        status = "selected" if scoring.priority == "high" else "classified" if scoring.priority == "medium" else "new"
        item_id = news_repo.get_item_id_by_key(conn, item_key)
        if item_id is None:
            item_id = repo.create_domain_item(
                conn,
                domain="news",
                item_type=item_type,
                title=payload.get("title") or "未命名条目",
                summary=payload.get("summary") or "暂无摘要",
                score=scoring.score,
                status=status,
                source=payload.get("source") or "unknown",
                source_url=payload.get("url") or "",
                primary_date=payload.get("primary_date") or "",
                tags=tags,
                metrics=metrics,
                payload=enriched,
            )
            news_repo.bind_item_key(conn, item_key, item_id)
            repo.create_evidence(
                conn,
                domain="news",
                domain_item_id=item_id,
                evidence_type="source_summary",
                title="来源摘要",
                content=payload.get("summary") or "原始来源未提供摘要。",
                source_url=payload.get("url") or "",
                confidence=classification.confidence,
                payload={"item_key": item_key, "run_id": run_id, "raw_artifact_ids": payload.get("raw_artifact_ids", [])},
            )
            created += 1
        else:
            news_repo.update_news_item(
                conn,
                item_id=item_id,
                item_type=item_type,
                title=payload.get("title") or "未命名条目",
                summary=payload.get("summary") or "暂无摘要",
                score=scoring.score,
                status=status,
                source=payload.get("source") or "unknown",
                source_url=payload.get("url") or "",
                primary_date=payload.get("primary_date") or "",
                tags=tags,
                metrics=metrics,
                payload=enriched,
            )
            news_repo.bind_item_key(conn, item_key, item_id)
            updated += 1
        item_ids.append(item_id)
    return {"created": created, "updated": updated, "items": len(item_ids), "item_ids": item_ids}


def _highlight(value: str) -> str:
    text = " ".join(value.split())
    for separator in ["。", ". ", "；", "; "]:
        if separator in text:
            text = text.split(separator, 1)[0]
            break
    return text[:180]
