from __future__ import annotations

import json
import base64
import urllib.parse
import urllib.request
from typing import Any

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.base_file import JsonFileConnector
from ai4sec_platform.sources.result import SourceFetchResult


class LiveJsonConnector(JsonFileConnector):
    connector_name = "live_json"
    source_type = "live_json"
    base_url = ""

    def health_check(self, config: dict) -> SourceHealth:
        settings = load_settings()
        if not settings.live_source_fetch_enabled:
            return SourceHealth(status="disabled", message="live_source_fetch_enabled=false")
        return SourceHealth(status="ok", message=self.base_url)

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        if request.config.get("path") or request.params.get("path"):
            return super().fetch(request)
        settings = load_settings()
        if not settings.live_source_fetch_enabled:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"live_source_fetch_enabled": False}, errors=["live_source_fetch_disabled"])
        url = self.build_url(request)
        try:
            raw = self.get_json(url)
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"url": url}, errors=[str(exc)])
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=self.extract_items(raw), metadata={"url": url, "raw_type": type(raw).__name__})

    def build_url(self, request: SourceFetchRequest) -> str:
        return self.base_url

    def get_json(self, url: str) -> Any:
        req = urllib.request.Request(url, headers={"User-Agent": "ai4sec-platform/0.1", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - explicit configured source
            return json.loads(resp.read().decode("utf-8"))

    def extract_items(self, raw: Any) -> list[dict[str, Any]]:
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
        if isinstance(raw, dict):
            for key in ["projects", "items", "results", "data", "repositories", "list"]:
                value = raw.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
        return []

    def extract_text(self, raw: Any) -> str:
        if not isinstance(raw, dict):
            return ""
        content = raw.get("content") or ""
        if not content:
            return ""
        try:
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception:
            return ""


def with_query(base: str, params: dict[str, Any]) -> str:
    clean = {key: value for key, value in params.items() if value not in {None, ""}}
    return f"{base}?{urllib.parse.urlencode(clean)}" if clean else base
