from __future__ import annotations


def build_capability_card(item: dict) -> dict:
    return {"item_type": "capability", "title": item.get("title", "未命名能力"), "payload": item}
