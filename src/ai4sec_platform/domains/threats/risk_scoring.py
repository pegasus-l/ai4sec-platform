from __future__ import annotations


def score_target(item: dict) -> float:
    return float(item.get("risk_score") or item.get("attack_surface_score") or item.get("score") or 0)
