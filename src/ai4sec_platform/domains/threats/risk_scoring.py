from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.threats.repo_vuln_extractors import extract_repo_vulnerability_signals
from ai4sec_platform.schemas.scoring import ScoreResult


def score_target(item: dict[str, Any]) -> float:
    return score_threat_item(item).score


def score_threat_item(item: dict[str, Any]) -> ScoreResult:
    payload = item.get("payload") or item
    source_type = payload.get("source_type") or item.get("source_type") or "asset"
    raw_score = _safe_float(payload.get("risk_score") or item.get("score"), 0.0)
    signals = extract_repo_vulnerability_signals(payload)
    cve_score = min(35.0, signals["cve_count"] * 7.0)
    security_signal_score = min(20.0, len(signals["security_hits"]) * 4.0 + signals["advisory_count"] * 5.0 + signals["security_issue_count"] * 2.0)
    exploit_score = 15.0 if signals["has_exploit_signal"] else 0.0
    exposure_score = _exposure_score(payload, source_type)
    inherited_score = min(30.0, raw_score * 0.3 if raw_score > 1 else raw_score * 30)
    total = min(100.0, cve_score + security_signal_score + exploit_score + exposure_score + inherited_score)
    if source_type in {"firmware", "mirror", "asset"} and total < raw_score:
        total = min(100.0, raw_score)
    priority = "critical" if total >= 90 else "high" if total >= 75 else "medium" if total >= 45 else "low"
    grade = "严重" if total >= 90 else "高" if total >= 75 else "中" if total >= 45 else "低"
    reasons = []
    if signals["cve_count"]:
        reasons.append(f"关联历史 CVE {signals['cve_count']} 个")
    if signals["security_hits"]:
        reasons.append(f"命中安全关键词：{', '.join(signals['security_hits'][:5])}")
    if exposure_score:
        reasons.append("存在固件/镜像/攻击面暴露线索")
    if raw_score:
        reasons.append("继承旧 raw 风险分作为参考信号")
    return ScoreResult(score=round(total, 2), priority=priority, grade=grade, breakdown={"cve": cve_score, "security_signals": security_signal_score, "exploit": exploit_score, "exposure": exposure_score, "inherited": round(inherited_score, 2)}, reasons=reasons or ["风险信号较少，保持观察"], signals={**signals, "source_type": source_type})


def _exposure_score(payload: dict[str, Any], source_type: str) -> float:
    if source_type == "firmware":
        return min(25.0, _safe_float(payload.get("risk_score"), 0) * 0.5)
    if source_type in {"mirror", "asset"}:
        return 12.0 if payload.get("url") else 5.0
    attack_surface = str(payload.get("attack_surface") or payload.get("primary_attack_surface") or "").lower()
    if any(term in attack_surface for term in ["web", "api", "network", "remote", "云", "网络"]):
        return 15.0
    return 0.0


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback
