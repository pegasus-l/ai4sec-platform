from __future__ import annotations

from typing import Any


def normalize_capability_candidate(item: dict[str, Any]) -> dict[str, Any]:
    """把 news domain_item 转成 capability_candidate 字段映射。

    输入: news domain_item（含 payload + score）
    输出: 候选 dict，字段对齐 CapabilityCandidate schema + 嵌入 source_news_item 反向引用

    迁移自旧 v1 db.py _resolve_repo_url + 字段对齐 demo today.json
    """
    payload = item.get("payload") or {}
    scoring = payload.get("scoring") or {}
    news_score = item.get("score") or scoring.get("score") or 0

    code_url = payload.get("code_url") or ""
    source_url = item.get("source_url") or payload.get("url") or ""

    # 推断 source_type
    if code_url or "github.com" in (source_url or "") or "gitlab.com" in (source_url or ""):
        source_type = "github"
    elif "arxiv.org" in (source_url or ""):
        source_type = "arxiv"
    else:
        source_type = payload.get("source_type") or "unknown"

    return {
        "title": item.get("title") or payload.get("title") or "未命名能力候选",
        "source_url": source_url,
        "code_url": code_url,
        "source_type": source_type,
        "source_news_score": float(news_score),
        "source_news_item": item,  # 反向引用原资讯（含原 score 作为先验）
        "status": "待能力评估",
    }
