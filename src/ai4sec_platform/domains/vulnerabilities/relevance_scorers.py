from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.vulnerabilities.material_classifiers import classify_material
from ai4sec_platform.schemas.scoring import ScoreResult


def score_material(item: dict[str, Any]) -> ScoreResult:
    classification = item.get("classification") or classify_material(item).as_payload()
    confidence = _safe_float(item.get("confidence"), 0.0)
    markdown_length = _safe_float(item.get("markdown_length"), 0.0)
    signals = classification.get("signals") or {}
    relevance = float(classification.get("confidence") or 0) * 35
    inherited = confidence * 25 if confidence <= 1 else min(25, confidence / 4)
    content_depth = min(15.0, markdown_length / 1500)
    poc = 15.0 if signals.get("poc_hits") else 0.0
    version = 8.0 if signals.get("version_hits") else 0.0
    noise_penalty = min(20.0, len(signals.get("noise_hits") or []) * 8.0)
    total = max(0.0, min(100.0, relevance + inherited + content_depth + poc + version - noise_penalty))
    priority = "high" if total >= 75 else "medium" if total >= 45 else "low"
    grade = "高" if total >= 75 else "中" if total >= 45 else "低"
    reasons = list(classification.get("reasons") or [])
    if content_depth:
        reasons.append("正文长度满足基础分析需求")
    if inherited:
        reasons.append("继承旧报告置信度作为参考信号")
    return ScoreResult(score=round(total, 2), priority=priority, grade=grade, breakdown={"classification": round(relevance, 2), "inherited_confidence": round(inherited, 2), "content_depth": round(content_depth, 2), "poc": poc, "version": version, "noise_penalty": noise_penalty}, reasons=reasons, signals=classification.get("signals") or {})


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback
