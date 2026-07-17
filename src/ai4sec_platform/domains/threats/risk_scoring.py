from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.threats.attack_surface_scoring import score_attack_surface
from ai4sec_platform.domains.threats.repo_vuln_extractors import extract_repo_vulnerability_signals
from ai4sec_platform.schemas.scoring import ScoreResult

SEVERITY_BONUS = {"critical": 30.0, "high": 18.0, "medium": 8.0, "low": 2.0, "unknown": 0.0, "": 0.0}


def score_target(item: dict[str, Any]) -> float:
    return score_threat_item(item).score


def score_threat_item(item: dict[str, Any]) -> ScoreResult:
    payload = item.get("payload") or item
    source_type = payload.get("source_type") or item.get("source_type") or "asset"
    attack_surface = score_attack_surface(payload)
    raw_score = _safe_float(payload.get("risk_score") or item.get("score"), 0.0)
    signals = extract_repo_vulnerability_signals(payload)
    cve_score = min(30.0, float(signals["cve_count"]) * 6.0)
    sa_score = min(10.0, float(signals["sa_count"]) * 3.0)
    broad_score = min(12.0, float(signals["valid_like_security_items"]) * 1.5)
    severity_score = SEVERITY_BONUS.get(str(signals.get("max_severity") or "unknown").lower(), 0.0)
    exploit_score = 20.0 if signals["has_exploit_signal"] else 0.0
    exposure_score = _exposure_score(payload, source_type)
    inherited_score = min(20.0, raw_score * 0.2 if raw_score > 1 else raw_score * 20)
    evidence_score = min(100.0, cve_score + sa_score + broad_score + severity_score + exploit_score + exposure_score + inherited_score)
    if source_type in {"repo", "repo_cve"}:
        total = max(attack_surface.score, evidence_score)
    else:
        total = max(evidence_score, min(100.0, raw_score), exposure_score)
    if attack_surface.signals.get("filtered"):
        total = min(total, 29.0)
    elif attack_surface.signals.get("deprioritized"):
        total = max(0.0, total - 8.0)
    priority = "critical" if total >= 90 else "high" if total >= 75 else "medium" if total >= 45 else "low"
    grade = "严重" if total >= 90 else "高" if total >= 75 else "中" if total >= 45 else "低"
    reasons = [*attack_surface.reasons]
    if signals["cve_count"]:
        reasons.append(f"关联历史 CVE {signals['cve_count']} 个")
    if signals["sa_count"]:
        reasons.append(f"关联安全公告 {signals['sa_count']} 个")
    if signals.get("max_severity") not in {"", "unknown"}:
        reasons.append(f"最高严重性 {signals['max_severity']}")
    if signals["has_security_repo_source"]:
        reasons.append("证据来自 security 子项目，可信度较高")
    if signals["has_project_issue_source"]:
        reasons.append("证据来自项目自身 issue，需要语义复核")
    if exploit_score:
        reasons.append("命中 exploit/PoC/RCE 线索")
    return ScoreResult(
        score=round(total, 2),
        priority=priority,
        grade=grade,
        breakdown={
            "legacy_attack_surface": attack_surface.score,
            "cve": cve_score,
            "security_advisory": sa_score,
            "broad_security": broad_score,
            "severity": severity_score,
            "exploit": exploit_score,
            "exposure": exposure_score,
            "inherited": round(inherited_score, 2),
        },
        reasons=reasons or ["风险信号较少，保持观察"],
        signals={
            **signals,
            "source_type": source_type,
            "legacy_attack_surface": attack_surface.as_payload(),
            "legacy_grade": attack_surface.grade,
            "filtered": attack_surface.signals.get("filtered", False),
            "filtered_reason": attack_surface.signals.get("filtered_reason", ""),
            "deprioritized": attack_surface.signals.get("deprioritized", False),
            "primary_attack_surface": attack_surface.signals.get("primary_attack_surface", ""),
        },
    )


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
