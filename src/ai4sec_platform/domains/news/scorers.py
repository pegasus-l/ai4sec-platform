"""统一规则评分器——7维（不含security维度），权重从YAML读。
security只做标记(flag)，不参与总分。安全项目和通用Agent项目一视同仁。
"""
from __future__ import annotations

import math
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai4sec_platform.domains.news.classifiers import classify_item
from ai4sec_platform.schemas.scoring import ScoreResult

_scoring_config: dict[str, Any] | None = None
_source_authority_config: dict[str, Any] | None = None


def _load_scoring_config(project_root: Path) -> dict[str, Any]:
    global _scoring_config
    if _scoring_config is None:
        path = project_root / "configs" / "scoring.yml"
        _scoring_config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return _scoring_config


def _load_source_authority(project_root: Path) -> dict[str, Any]:
    global _source_authority_config
    if _source_authority_config is None:
        path = project_root / "configs" / "source_authority.yml"
        _source_authority_config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return _source_authority_config


def score_candidate(item: dict[str, Any], project_root: Path) -> ScoreResult:
    """对原始item做7维规则评分。不调LLM，纯规则+元数据。"""
    config = _load_scoring_config(project_root)
    classification = item.get("classification") or classify_item(item)
    if isinstance(classification, ClassificationResult):
        classification = classification.as_payload()

    payload = item.get("payload") or item.get("normalized") or item
    source_type = payload.get("source_type") or item.get("source_type") or "article"

    # --- 7 维度 ---
    # 1. relevance: 分类置信度 × 100
    relevance = float(classification.get("confidence", 0.35)) * 100

    # 2. code_clue: 有code_url→100, 无→0
    code_url = item.get("code_url") or payload.get("code_url") or ""
    has_code = 1.0 if code_url else 0.0
    code_clue = has_code * 100

    # 3. reproducibility: 0.5×has_code + 0.3×stars_factor + 0.2×has_readme, 归一化100
    stars = float(payload.get("stars") or item.get("stars") or 0)
    stars_factor = min(1.0, math.log10(stars + 1) / 4.0)  # 10000 stars → 1.0
    has_readme = 1.0 if (payload.get("summary") or item.get("summary") or payload.get("description")) else 0.0
    reproducibility = (0.5 * has_code + 0.3 * stars_factor + 0.2 * has_readme) * 100

    # 4. influence: log10(stars)×25, 文章固定40
    influence = min(100.0, math.log10(max(1, stars)) * 25) if source_type in ("project", "github") else 40.0

    # 5. freshness: 从YAML读freshness_score表
    freshness = _freshness_score(payload.get("primary_date") or payload.get("published_at") or item.get("published_at"), config)

    # 6. source_authority: 从source_authority.yml查
    source_authority = _resolve_source_authority(item, project_root)

    # 7. completeness: 有summary/url/authors/topics 各+25
    completeness = min(100, sum(25 for f in ["summary", "url", "authors", "topics"] if payload.get(f) or item.get(f)))

    breakdown = {
        "relevance": round(relevance, 2),
        "code_clue": round(code_clue, 2),
        "reproducibility": round(reproducibility, 2),
        "influence": round(influence, 2),
        "freshness": freshness,
        "source_authority": source_authority,
        "completeness": completeness,
    }

    # 加权
    weights_key = "paper_weights" if source_type in ("paper", "arxiv") else "project_weights"
    weights = config.get(weights_key, config.get("project_weights", {}))
    total = round(min(100.0, sum(breakdown.get(k, 0) * w for k, w in weights.items())), 2)

    thresholds = config.get("rule_thresholds", {})
    if total < thresholds.get("skip", 40):
        decision = "skip"
    elif total < thresholds.get("news_only", 55) or not has_code:
        decision = "news_only"
    else:
        decision = "enter_llm"

    signals = classification.get("signals", {}) if isinstance(classification, dict) else {}
    return ScoreResult(
        score=total,
        priority="high" if total >= 75 else "medium" if total >= 48 else "low",
        grade="高" if total >= 75 else "中" if total >= 48 else "低",
        breakdown=breakdown,
        reasons=classification.get("reasons", []) if isinstance(classification, dict) else [],
        signals={
            **signals,
            "decision": decision,
            "has_code": bool(has_code),
            "code_url": code_url,
            "stars_factor": round(stars_factor, 3),
            "source_type": source_type,
            "security_flag": signals.get("security_flag", False),
            "security_topics": signals.get("security_topics", []),
        },
    )


def _freshness_score(value: Any, config: dict[str, Any]) -> float:
    if not value:
        for entry in config.get("freshness_score", []):
            if entry.get("no_date"):
                return float(entry["score"])
        return 10.0
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        age_hours = max(0, (datetime.now(timezone.utc) - parsed).total_seconds() / 3600)
    except (TypeError, ValueError):
        return 20.0
    for entry in config.get("freshness_score", []):
        max_h = entry.get("max_hours")
        if max_h is not None and age_hours <= max_h:
            return float(entry["score"])
    return 20.0


def _resolve_source_authority(item: dict[str, Any], project_root: Path) -> float:
    """从source_authority.yml查来源权威分。"""
    auth_config = _load_source_authority(project_root)
    sources = auth_config.get("sources", {})
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    raw_json = item.get("raw_json") if isinstance(item.get("raw_json"), dict) else {}
    source_type = (raw.get("source_type") or raw_json.get("source_type") or item.get("source_type") or "").lower()
    source_url = str(item.get("source_url") or item.get("url") or raw_json.get("url") or "")

    # 直接匹配 source_type
    if source_type in sources:
        return float(sources[source_type])

    # RSS: 查 overrides
    if source_type in ("rss", "feed"):
        rss_cfg = sources.get("rss", {})
        overrides = rss_cfg.get("overrides", {})
        for url_prefix, score in overrides.items():
            if source_url.startswith(url_prefix):
                return float(score)
        return float(rss_cfg.get("default", 40))

    # 官方博客: 匹配 URL
    official = sources.get("official_blogs", [])
    if isinstance(official, list):
        for entry in official:
            if isinstance(entry, dict) and source_url.startswith(entry.get("url", "")):
                return float(entry.get("score", 50))

    return float(sources.get("unknown", 50))


# 避免循环导入——延迟导入 ClassificationResult
from ai4sec_platform.schemas.classification import ClassificationResult as _CR  # noqa: E402
