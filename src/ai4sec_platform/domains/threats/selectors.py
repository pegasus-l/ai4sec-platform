from __future__ import annotations


def select_high_risk(items: list[dict], threshold: float = 80) -> list[dict]:
    return [item for item in items if float(item.get("risk_score") or item.get("score") or 0) >= threshold]
