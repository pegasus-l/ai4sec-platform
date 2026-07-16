from __future__ import annotations


def build_material(item: dict) -> dict:
    return {"item_type": "material", "title": item.get("title", "未命名漏洞素材"), "payload": item}
