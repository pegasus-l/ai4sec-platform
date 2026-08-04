from __future__ import annotations

import re
from typing import Any

from ai4sec_platform.domains.capabilities.normalizers import normalize_capability_candidate

# 资讯 score 阈值：低于此值不派生为能力候选（对齐 news/builders.py 第 45 行 scoring.score >= 55）
DEFAULT_SCORE_THRESHOLD = 55.0


def capability_candidates_from_news(
    items: list[dict[str, Any]],
    *,
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
    require_code: bool = True,
) -> list[dict[str, Any]]:
    """从资讯 domain_items 派生能力候选。

    筛选规则（迁自旧 v1 news/builders.py 第 45 行 + 旧 v1 db.py pick_top_repro_candidates）：
      1. 资讯 score >= score_threshold（默认 55）
      2. 有 code_url 或 source_type=repo 或 source_url 含 github.com（require_code=True 时）

    返回: 候选 dict 列表，每个含 normalize 后的字段 + source_news_item 反向引用。
          候选 dict 字段对齐 CapabilityCandidate schema。
    """
    candidates: list[dict[str, Any]] = []
    seen_repo_keys: set[str] = set()  # B: org/repo 去重(避免同项目不同 trending date 重复)
    for item in items:
        payload = item.get("payload") or {}
        scoring = payload.get("scoring") or {}
        news_score = float(item.get("score") or scoring.get("score") or 0)
        if news_score < score_threshold:
            continue

        code_url = payload.get("code_url") or ""
        source_url = item.get("source_url") or payload.get("url") or ""
        source_type = payload.get("source_type") or ""

        has_code = bool(code_url) or source_type == "repo" or "github.com" in (source_url or "")
        if require_code and not has_code:
            continue

        # B: 从 URL 提取 org/repo 作为去重 key
        repo_match = re.search(r'github\.com/([^/]+/[^/?]+)', (code_url or source_url or "").lower())
        if repo_match:
            repo_key = repo_match.group(1)
            if repo_key in seen_repo_keys:
                continue
            seen_repo_keys.add(repo_key)

        candidate = normalize_capability_candidate(item)
        candidates.append(candidate)
    return candidates


def list_capability_candidates_from_db(
    conn,
    *,
    limit: int = 100,
    score_threshold: float = DEFAULT_SCORE_THRESHOLD,
    require_code: bool = True,
) -> list[dict[str, Any]]:
    """从 DB 读 news domain_items 并派生能力候选（供 capabilities.from_news_pipeline 使用）"""
    from ai4sec_platform.db import repositories as repo

    news_items = repo.list_domain_items(conn, "news", limit=limit * 3)  # 多读一些，过滤后保留 limit 个
    candidates = capability_candidates_from_news(
        news_items,
        score_threshold=score_threshold,
        require_code=require_code,
    )
    return candidates[:limit]
