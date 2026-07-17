from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.news.classifiers import classify_news_item
from ai4sec_platform.schemas.scoring import ScoreResult


def score_news_item(item: dict[str, Any]) -> ScoreResult:
    classification = item.get("classification") or classify_news_item(item).as_payload()
    payload = item.get("payload") or item.get("normalized") or item
    source_type = payload.get("source_type") or item.get("source_type") or "article"
    relevance = float(classification.get("confidence") or 0.0) * 45
    code = 20 if payload.get("code_url") or source_type == "repo" else 0
    vuln = 15 if classification.get("category") == "漏洞与攻防" else 0
    agent_security = 15 if classification.get("category") == "Agent 安全" else 0
    influence = min(10.0, float(payload.get("stars") or 0) / 1000) if source_type == "repo" else 3
    freshness = 7 if payload.get("primary_date") else 3
    total = min(100.0, relevance + code + vuln + agent_security + influence + freshness)
    priority = "high" if total >= 75 else "medium" if total >= 45 else "low"
    grade = "高" if total >= 75 else "中" if total >= 45 else "低"
    reasons = list(classification.get("reasons") or [])
    if code:
        reasons.append("具备代码/仓库线索，可转入能力评估")
    return ScoreResult(score=round(total, 2), priority=priority, grade=grade, breakdown={"relevance": round(relevance, 2), "code": code, "vulnerability": vuln, "agent_security": agent_security, "influence": round(influence, 2), "freshness": freshness}, reasons=reasons, signals={"category": classification.get("category"), "source_type": source_type})
