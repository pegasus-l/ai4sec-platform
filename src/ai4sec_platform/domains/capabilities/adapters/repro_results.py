from __future__ import annotations


def normalize_repro_result(item: dict) -> dict:
    return {"repro_status": item.get("status", "unknown"), **item}
