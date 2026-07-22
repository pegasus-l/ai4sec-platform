from __future__ import annotations

import math
from typing import Any

from ai4sec_platform.schemas.scoring import ScoreResult


def score_capability_candidate(item: dict[str, Any]) -> ScoreResult:
    """多维度能力评分（决策 6：资讯 score 作为先验信号，不直接继承）。

    5 维度：
      - relevance:        0.4 * 资讯分归一化 + 0.6 * 主题相关性信号
      - code_clue:        有无 code_url（0 or 1）
      - reproducibility:  0.5 * has_code + 0.3 * stars_factor + 0.2 * has_readme
      - research_value:   0.7 * 资讯分 + 0.3 * 学术信号
      - security_value:   安全主题命中（1.0）或弱相关（0.3）

    最终 score 映射到 1-5（对齐 demo today.json 的 score 字段）。
    资讯 score 存在 news domain_items（1-10），能力 score 存在 capabilities domain_items（1-5），
    两者独立、互不覆盖。
    """
    payload: dict[str, Any] = item.get("payload") or {}
    # 兼容两种输入：候选 dict（含 source_news_item）或直接 news item
    source_news = payload.get("source_news_item")
    news_item: dict[str, Any] = source_news if isinstance(source_news, dict) else item
    news_score = float(news_item.get("score") or 0) / 10.0  # 归一化 0-1（资讯分 1-10）

    code_url = item.get("code_url") or payload.get("code_url") or news_item.get("code_url") or ""
    has_code = 1.0 if code_url else 0.0

    stars = float(news_item.get("stars") or payload.get("stars") or 0)
    stars_factor = min(math.log10(stars + 1) / 4.0, 1.0)  # 10K stars → 1.0

    has_readme = 1.0 if (news_item.get("highlight") or news_item.get("summary") or payload.get("summary")) else 0.0

    # 信号检测（迁自旧 scorers.py 关键词列表 + 扩展）
    text_parts = [news_item.get("title"), news_item.get("summary"), news_item.get("source_url"), code_url, payload.get("title")]
    text = " ".join(str(p) for p in text_parts if p).lower()
    has_relevance_signals = any(t in text for t in ["ai", "security", "agent", "llm", "model", "code", "audit", "tool", "framework"])
    has_academic = any(t in text for t in ["arxiv", "paper", "论文", "research", "study"])
    has_security_topic = any(t in text for t in ["security", "vulnerability", "cve", "attack", "安全", "漏洞", "exploit"])

    breakdown = {
        "relevance": 0.4 * news_score + 0.6 * (1.0 if has_relevance_signals else 0.0),
        "code_clue": has_code,
        "reproducibility": 0.5 * has_code + 0.3 * stars_factor + 0.2 * has_readme,
        "research_value": 0.7 * news_score + 0.3 * (1.0 if has_academic else 0.0),
        "security_value": 1.0 if has_security_topic else 0.3,
    }
    final = sum(breakdown.values()) / len(breakdown)  # 0-1
    score = max(1, min(5, round(final * 5)))  # 映射到 1-5
    priority = "high" if score >= 4 else "medium" if score >= 3 else "low"
    grade = "高" if score >= 4 else "中" if score >= 3 else "低"

    return ScoreResult(
        score=float(score),
        priority=priority,
        grade=grade,
        breakdown=breakdown,
        reasons=[
            f"资讯分={news_score * 10:.0f}/10 作为先验" + ("（高）" if news_score > 0.7 else "（中）" if news_score > 0.4 else "（低）"),
            "有可复现代码" if has_code else "无可复现代码",
            "安全主题命中" if has_security_topic else "安全主题未命中",
            f"GitHub stars 归一化={stars_factor:.2f}" if stars > 0 else "无 stars 数据",
        ],
        signals={
            "has_code": bool(has_code),
            "has_academic": has_academic,
            "has_security_topic": has_security_topic,
            "stars_factor": round(stars_factor, 3),
            "news_score_normalized": round(news_score, 3),
        },
    )
