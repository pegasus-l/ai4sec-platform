from __future__ import annotations

import sqlite3

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.news.classifiers import classify_news_item
from ai4sec_platform.domains.news.scorers import score_news_item


def build_news_and_capability_items(conn: sqlite3.Connection, items: list[dict], *, run_id: str) -> dict[str, int]:
    news_count = 0
    capability_count = 0
    for item in items:
        payload = repo.loads(item.get("normalized_json"), {})
        classification = classify_news_item(payload)
        scoring = score_news_item({**payload, "classification": classification.as_payload()})
        tags = ["raw_pipeline", payload.get("source_type") or item.get("source_type"), classification.category, *classification.tags]
        news_id = repo.create_domain_item(
            conn,
            domain="news",
            item_type="raw_pipeline_item",
            title=payload.get("title") or item.get("title") or "未命名条目",
            summary=payload.get("summary") or "来自 AI-for-Sec raw pipeline，待模型审阅。",
            score=scoring.score,
            status="重点审阅" if scoring.priority == "high" else "待审阅" if scoring.priority == "medium" else "低优先级",
            source=payload.get("source") or item.get("source") or "raw_pipeline",
            source_url=payload.get("url") or item.get("url") or "",
            primary_date=payload.get("primary_date") or item.get("primary_date") or "",
            tags=[tag for tag in tags if tag],
            metrics={"pipeline_run": run_id, "classification_confidence": classification.confidence, "score_breakdown": scoring.breakdown},
            payload={**payload, "classification": classification.as_payload(), "scoring": scoring.as_payload()},
        )
        news_count += 1
        repo.create_evidence(
            conn,
            domain="news",
            domain_item_id=news_id,
            evidence_type="raw_summary",
            title="Raw pipeline 摘要",
            content=payload.get("summary") or "已生成资讯证据，正文补全可由后续内容抓取阶段增强。",
            source_url=payload.get("url") or "",
            confidence=classification.confidence,
            payload={"item_key": item.get("item_key"), "run_id": run_id, "classification": classification.as_payload(), "scoring": scoring.as_payload()},
        )
        if scoring.score >= 55 and (payload.get("source_type") == "repo" or payload.get("code_url")):
            capability_id = repo.create_domain_item(
                conn,
                domain="capabilities",
                item_type="raw_capability_candidate",
                title=payload.get("title") or item.get("title") or "未命名能力候选",
                summary=payload.get("summary") or "来自 raw pipeline 的能力候选，待复现评估。",
                score=scoring.score,
                status="待能力评估",
                source="raw_pipeline",
                source_url=payload.get("code_url") or payload.get("url") or "",
                primary_date=payload.get("primary_date") or "",
                tags=["raw_pipeline", "能力候选", classification.category],
                metrics={"pipeline_run": run_id, "source_news_score": scoring.score},
                payload={**payload, "classification": classification.as_payload(), "scoring": scoring.as_payload()},
            )
            capability_count += 1
            repo.create_human_queue_item(
                conn,
                domain="capabilities",
                item_id=capability_id,
                queue_type="capability_assessment",
                priority=3,
                reason="Raw pipeline 识别到代码/仓库候选，等待能力评估或复现判断。",
                payload={"run_id": run_id, "item_key": item.get("item_key")},
            )
    return {"news": news_count, "capabilities": capability_count}
