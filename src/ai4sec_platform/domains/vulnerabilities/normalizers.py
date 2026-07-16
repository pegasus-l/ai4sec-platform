from __future__ import annotations


def normalize_material(item: dict) -> dict:
    return {"title": item.get("title") or item.get("url") or "未命名漏洞素材", **item}
