from __future__ import annotations

import sqlite3
from typing import Any
from pathlib import Path

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.news import repository as news_repo
from ai4sec_platform.domains.news.classifiers import classify_news_item
from ai4sec_platform.domains.news.scorers import score_news_item
from ai4sec_platform.domains.news.tech_map import AgentTechMap


def build_news_items(conn: sqlite3.Connection, items: list[dict[str, Any]], *, run_id: str) -> dict[str, Any]:
    created = 0
    updated = 0
    item_ids: list[int] = []
    for payload in items:
        review = payload.get("review") if isinstance(payload.get("review"), dict) else {}
        if not review:
            fallback_paths = AgentTechMap.load(Path(__file__).parents[4]).fallback_paths(payload)
            review = {"tech_paths": fallback_paths, "technical_points": [path["point"] for path in fallback_paths], "topic": fallback_paths[0]["category"] if fallback_paths else "", "score": None, "confidence": 0.25}
        fallback_classification = classify_news_item(payload)
        fallback_scoring = score_news_item({**payload, "classification": fallback_classification.as_payload()})
        item_key = str(payload["item_key"])
        item_type = str(payload.get("source_type") or "")
        if item_type not in {"paper", "project"}:
            continue
        tech_paths = review.get("tech_paths") if isinstance(review.get("tech_paths"), list) else []
        technical_points = list(dict.fromkeys(review.get("technical_points") or [path.get("point") for path in tech_paths if isinstance(path, dict)]))[:10]
        display_topic = str(review.get("topic") or fallback_classification.category)
        display_theme = str(review.get("theme") or payload.get("title") or "未命名条目")
        one_liner = str(review.get("promo_line") or _one_liner(item_type, display_topic, payload.get("title") or ""))
        summary = str(review.get("summary_zh") or payload.get("summary") or "暂无摘要")
        score = float(review.get("score") if review.get("score") is not None else fallback_scoring.score)
        scoring_payload = {
            "score": score,
            "priority": "high" if score >= 75 else "medium" if score >= 48 else "low",
            "grade": "高" if score >= 75 else "中" if score >= 48 else "低",
            "breakdown": review.get("score_breakdown") or fallback_scoring.breakdown,
            "reasons": [review.get("review_reason")] if review.get("review_reason") else fallback_scoring.reasons,
            "signals": {"source": "model_review" if review else "rule_fallback"},
        }
        classification_payload = {
            "dimension": tech_paths[0].get("dimension", "") if tech_paths else "",
            "category": display_topic,
            "subcategory": display_topic,
            "tech_paths": tech_paths,
            "tags": technical_points,
            "confidence": review.get("confidence", fallback_classification.confidence),
            "reasons": [review.get("review_reason")] if review.get("review_reason") else fallback_classification.reasons,
        }
        enriched = {
            **payload,
            "summary": summary,
            "highlight": str(review.get("highlight_line") or _highlight(summary or payload.get("title") or "")),
            "display_topic": display_topic,
            "display_theme": display_theme,
            "one_liner": one_liner,
            "technical_points": technical_points,
            "tech_paths": tech_paths,
            "classification": classification_payload,
            "scoring": scoring_payload,
            "pipeline_run": run_id,
        }
        tags = list(dict.fromkeys([item_type, display_topic, *technical_points]))
        metrics = {"pipeline_run": run_id, "classification_confidence": classification_payload["confidence"], "score_breakdown": scoring_payload["breakdown"], "tech_map_version": review.get("tech_map_version", "")}
        status = "selected" if score >= 75 else "classified"
        item_id = news_repo.get_item_id_by_key(conn, item_key)
        if item_id is None:
            item_id = repo.create_domain_item(
                conn,
                domain="news",
                item_type=item_type,
                title=payload.get("title") or "未命名条目",
                summary=summary,
                score=score,
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
                confidence=float(classification_payload["confidence"] or 0),
                payload={"item_key": item_key, "run_id": run_id, "raw_artifact_ids": payload.get("raw_artifact_ids", [])},
            )
            created += 1
        else:
            news_repo.update_news_item(
                conn,
                item_id=item_id,
                item_type=item_type,
                title=payload.get("title") or "未命名条目",
                summary=summary,
                score=score,
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


def _one_liner(item_type: str, topic: str, title: str) -> str:
    subject = "前沿论文" if item_type == "paper" else "开源项目"
    concise_title = " ".join(title.split())[:72]
    return f"{subject}聚焦「{topic}」：{concise_title}"
