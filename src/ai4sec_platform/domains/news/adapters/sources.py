from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ai4sec_platform.core.config import Settings
from ai4sec_platform.domains.news.adapters.ai_for_sec_raw import load_raw_sources
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.registry import SourceRegistry


def collect_news_sources(settings: Settings, params: dict[str, Any]) -> list[dict[str, Any]]:
    mode = str(params.get("mode") or "shadow")
    if mode in {"legacy_raw", "fixture"}:
        date = str(params.get("date") or "")
        if not date:
            raise ValueError(f"{mode} mode requires date")
        raw_dir = Path(params.get("fixture_dir") or settings.legacy_sources.get("ai_for_sec_raw_dir", ""))
        return [{**record, "mode": mode, "errors": []} for record in load_raw_sources(raw_dir, date)]
    config = _load_config(settings.project_root)
    registry = SourceRegistry()
    source_names = ["arxiv", "github", "rss", "x", "asis", "awesome"]
    requested = set(params["sources"]) if "sources" in params else set(source_names)
    records: list[dict[str, Any]] = []
    for source in source_names:
        source_config = config.get("sources", {}).get(source, {})
        if source not in requested or not source_config.get("enabled", True):
            continue
        connector = registry.get(source)
        if source in {"arxiv", "github"}:
            items: list[dict[str, Any]] = []
            errors: list[str] = []
            metadata: list[dict[str, Any]] = []
            for query in source_config.get("queries") or []:
                result = connector.fetch(SourceFetchRequest(source_name=source, config=source_config, params={"query": query, "max_results": params.get("max_results") or source_config.get("max_results", 30), "timeout_seconds": params.get("timeout_seconds", 30)}))
                items.extend(result.items)
                errors.extend(result.errors)
                metadata.append(result.metadata)
            records.append({"source": source, "path": f"connector:{source}", "exists": True, "mode": mode, "items": items, "errors": errors, "metadata": metadata})
        else:
            result = connector.fetch(SourceFetchRequest(source_name=source, config=source_config, params={"urls": source_config.get("urls", []), "timeout_seconds": params.get("timeout_seconds", 30)}))
            records.append({"source": source, "path": f"connector:{source}", "exists": True, "mode": mode, "items": result.items, "errors": result.errors, "metadata": result.metadata})
    return records


def _load_config(project_root: Path) -> dict[str, Any]:
    path = project_root / "configs" / "news.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
