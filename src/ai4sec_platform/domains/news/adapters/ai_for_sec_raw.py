from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SOURCE_FILES = {
    "arxiv": "arxiv_{date_compact}.json",
    "github": "github_{date_compact}.json",
    "rss": "rss_new_candidates_{date_compact}.json",
    "x": "x_new_candidates_{date_compact}.json",
    "asis": "asis_new_candidates_{date_compact}.json",
    "awesome": "awesome_candidates_{date_compact}.json",
}


def load_raw_sources(raw_dir: Path, date: str) -> list[dict[str, Any]]:
    date_compact = date.replace("-", "")
    sources: list[dict[str, Any]] = []
    for source, pattern in SOURCE_FILES.items():
        path = raw_dir / pattern.format(date_compact=date_compact)
        if not path.exists():
            sources.append({"source": source, "path": str(path), "exists": False, "items": []})
            continue
        data = _read_json(path)
        items = extract_items(source, data)
        sources.append({"source": source, "path": str(path), "exists": True, "items": items, "raw": data})
    return sources


def extract_items(source: str, data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ["items", "entries", "candidates", "papers", "repos", "results", "new_candidates"]:
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if source == "github" and isinstance(data.get("repositories"), list):
        return [item for item in data["repositories"] if isinstance(item, dict)]
    if source in {"rss", "x", "asis", "awesome"}:
        refs: list[dict[str, Any]] = []
        for key in ["new_papers", "new_repos", "paper_refs", "repo_refs", "high_value_items"]:
            value = data.get(key)
            if isinstance(value, list):
                refs.extend(item for item in value if isinstance(item, dict))
        if refs:
            return refs
    return []


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
