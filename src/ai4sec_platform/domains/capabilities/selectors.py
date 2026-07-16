from __future__ import annotations


def select_for_assessment(items: list[dict]) -> list[dict]:
    return [item for item in items if item.get("source_url") or item.get("code_url")]
