from __future__ import annotations


def normalize_target(item: dict) -> dict:
    return {"title": item.get("title") or item.get("full_name") or item.get("name") or "未命名目标", **item}
