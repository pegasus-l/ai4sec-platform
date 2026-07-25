from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

from ai4sec_platform.domains.news.classifiers import classify_news_item
from ai4sec_platform.schemas.scoring import ScoreResult


def score_news_item(item: dict[str, Any]) -> ScoreResult:
    classification = item.get("classification") or classify_news_item(item).as_payload()
    payload = item.get("payload") or item.get("normalized") or item
    source_type = payload.get("source_type") or item.get("source_type") or "article"
    relevance = float(classification.get("confidence") or 0.0) * 45
    security = 18 if classification.get("category") in {"漏洞与攻防", "Agent 安全", "AI 安全研究"} else 8 if classification.get("category") == "安全工具与代码" else 0
    reproducibility = 12 if payload.get("code_url") else 8 if source_type == "project" else 0
    influence = min(12.0, math.log10(max(1, int(payload.get("stars") or 0))) * 3) if source_type == "project" else 5
    freshness = _freshness_score(payload.get("primary_date") or payload.get("updated_at"))
    completeness = min(8, sum(2 for field in ["summary", "url", "authors", "topics"] if payload.get(field)))
    total = min(100.0, relevance + security + reproducibility + influence + freshness + completeness)
    priority = "high" if total >= 75 else "medium" if total >= 48 else "low"
    grade = "高" if total >= 75 else "中" if total >= 48 else "低"
    reasons = list(classification.get("reasons") or [])
    if reproducibility:
        reasons.append("具备代码或项目线索")
    if freshness >= 10:
        reasons.append("近期发布或更新")
    return ScoreResult(
        score=round(total, 2),
        priority=priority,
        grade=grade,
        breakdown={
            "relevance": round(relevance, 2),
            "security": security,
            "reproducibility": reproducibility,
            "influence": round(influence, 2),
            "freshness": freshness,
            "completeness": completeness,
        },
        reasons=reasons,
        signals={"category": classification.get("category"), "source_type": source_type},
    )


def _freshness_score(value: Any) -> float:
    if not value:
        return 2
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age_days = max(0, (datetime.now(timezone.utc) - parsed).days)
    except (TypeError, ValueError):
        return 4
    if age_days <= 2:
        return 15
    if age_days <= 7:
        return 12
    if age_days <= 30:
        return 8
    if age_days <= 90:
        return 4
    return 1
