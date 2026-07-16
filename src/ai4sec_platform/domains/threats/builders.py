from __future__ import annotations


def build_threat_target(item: dict) -> dict:
    return {"item_type": "target", "title": item.get("title", "未命名目标"), "payload": item}
