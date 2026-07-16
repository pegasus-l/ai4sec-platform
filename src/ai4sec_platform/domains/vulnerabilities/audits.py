from __future__ import annotations


def audit_materials(items: list[dict]) -> dict:
    return {"count": len(items), "missing_url": sum(1 for item in items if not item.get("url") and not item.get("source_url"))}
