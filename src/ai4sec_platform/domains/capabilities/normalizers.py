from __future__ import annotations


def normalize_capability_candidate(item: dict) -> dict:
    return {"title": item.get("title") or item.get("name") or "未命名能力", **item}
