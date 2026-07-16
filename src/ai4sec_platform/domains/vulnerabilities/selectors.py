from __future__ import annotations


def select_for_knowledge(items: list[dict]) -> list[dict]:
    return [item for item in items if item.get("is_relevant") or item.get("confidence")]
