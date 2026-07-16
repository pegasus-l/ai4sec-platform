from __future__ import annotations

from ai4sec_platform.db import repositories as repo


def dedupe_normalized_items(items: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for item in items:
        key = item.get("item_key") or item.get("id")
        normalized = repo.loads(item.get("normalized_json"), {})
        if key not in seen:
            seen[key] = dict(item)
            continue
        existing = seen[key]
        existing_payload = repo.loads(existing.get("normalized_json"), {})
        sources = set(existing_payload.get("discovered_from") or [existing.get("source")])
        sources.add(item.get("source"))
        existing_payload["discovered_from"] = sorted(source for source in sources if source)
        if not existing_payload.get("summary") and normalized.get("summary"):
            existing_payload["summary"] = normalized.get("summary")
        if not existing_payload.get("code_url") and normalized.get("code_url"):
            existing_payload["code_url"] = normalized.get("code_url")
        existing["normalized_json"] = repo.dumps(existing_payload)
    return list(seen.values())
