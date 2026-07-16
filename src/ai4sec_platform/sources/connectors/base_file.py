from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.result import SourceFetchResult


class JsonFileConnector:
    connector_name = "json_file"
    source_type = "json_file"

    def health_check(self, config: dict) -> SourceHealth:
        path = Path(config.get("path", ""))
        if path.exists():
            return SourceHealth(status="ok", message=str(path))
        return SourceHealth(status="missing", message=str(path))

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        path = Path(request.config.get("path") or request.params.get("path") or "")
        if not path.exists():
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"path": str(path)}, errors=["missing_path"])
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"path": str(path)}, errors=[str(exc)])
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=extract_items(raw), metadata={"path": str(path), "raw_type": type(raw).__name__})


class PlaceholderConnector(JsonFileConnector):
    connector_name = "placeholder"
    source_type = "placeholder"


def extract_items(raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if not isinstance(raw, dict):
        return []
    for key in ["items", "entries", "candidates", "papers", "repos", "repositories", "projects", "results", "new_candidates"]:
        value = raw.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    refs: list[dict[str, Any]] = []
    for key in ["paper_refs", "repo_refs", "high_value_items"]:
        value = raw.get(key)
        if isinstance(value, list):
            refs.extend(item for item in value if isinstance(item, dict))
    return refs
