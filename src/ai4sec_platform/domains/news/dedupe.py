from __future__ import annotations

from typing import Any

from ai4sec_platform.db import repositories as repo


def dedupe_normalized_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[str, dict[str, Any]] = {}
    for row in items:
        item = _payload(row)
        key = str(item.get("item_key") or row.get("item_key") or row.get("id") or "")
        if not key:
            continue
        item["item_key"] = key
        if row.get("raw_artifact_id"):
            item["raw_artifact_ids"] = [row["raw_artifact_id"]]
        if key not in deduped:
            deduped[key] = item
        else:
            deduped[key] = merge_news_items(deduped[key], item)
    return list(deduped.values())


def merge_news_items(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    sources = set(existing.get("discovered_from") or [existing.get("source")])
    sources.update(incoming.get("discovered_from") or [incoming.get("source")])
    merged["discovered_from"] = sorted(str(source) for source in sources if source)
    for field in ["summary", "code_url", "paper_url", "repo_full_name", "language", "updated_at", "external_id"]:
        if not merged.get(field) and incoming.get(field):
            merged[field] = incoming[field]
    for field in ["authors", "topics", "raw_artifact_ids"]:
        values = [*(merged.get(field) or []), *(incoming.get(field) or [])]
        merged[field] = list(dict.fromkeys(value for value in values if value))
    for field in ["stars", "forks"]:
        merged[field] = max(int(merged.get(field) or 0), int(incoming.get(field) or 0))
    if incoming.get("primary_date") and incoming["primary_date"] > str(merged.get("primary_date") or ""):
        merged["primary_date"] = incoming["primary_date"]
    return merged


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    if isinstance(row.get("normalized"), dict):
        return dict(row["normalized"])
    if "normalized_json" in row:
        return repo.loads(row.get("normalized_json"), {})
    return dict(row)
