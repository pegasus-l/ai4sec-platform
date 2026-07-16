from __future__ import annotations


def audit_capability_items(items: list[dict]) -> dict:
    return {"count": len(items), "missing_source_url": sum(1 for item in items if not item.get("source_url"))}
