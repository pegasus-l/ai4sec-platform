from __future__ import annotations

from typing import Any

from ai4sec_platform.schemas.scoring import ScoreResult


def score_capability_candidate(item: dict[str, Any]) -> ScoreResult:
    payload = item.get("payload") or item.get("source_news_item", {}).get("payload") or item
    source_item = payload.get("source_news_item") if isinstance(payload.get("source_news_item"), dict) else payload
    text = " ".join(str(source_item.get(key, "")) for key in ["title", "summary", "source_url", "code_url"]).lower()
    has_repo = any(token in text for token in ["github.com", "gitlab", "repo", "repository"])
    has_paper = any(token in text for token in ["arxiv", "paper", "论文"])
    has_security = any(token in text for token in ["security", "vulnerability", "cve", "attack", "安全", "漏洞"])
    reproducibility = 35 if has_repo else 12
    research_value = 20 if has_paper else 8
    security_value = 25 if has_security else 10
    implementation = 10 if source_item.get("code_url") or has_repo else 0
    total = min(100.0, reproducibility + research_value + security_value + implementation)
    priority = "high" if total >= 75 else "medium" if total >= 45 else "low"
    return ScoreResult(score=round(total, 2), priority=priority, grade="高" if total >= 75 else "中" if total >= 45 else "低", breakdown={"reproducibility": reproducibility, "research_value": research_value, "security_value": security_value, "implementation": implementation}, reasons=["包含可评估代码仓库" if has_repo else "缺少明确代码仓库", "包含安全主题" if has_security else "安全主题需要复核"], signals={"has_repo": has_repo, "has_paper": has_paper, "has_security": has_security})
