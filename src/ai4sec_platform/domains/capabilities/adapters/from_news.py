from __future__ import annotations


def capability_candidates_from_news(items: list[dict]) -> list[dict]:
    return [item for item in items if item.get("source_url") or item.get("payload", {}).get("code_url")]
