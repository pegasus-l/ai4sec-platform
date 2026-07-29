from __future__ import annotations

import json
import base64
import urllib.parse
import urllib.request
from typing import Any

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.base_file import JsonFileConnector
from ai4sec_platform.sources.result import SourceFetchResult


class LiveJsonConnector(JsonFileConnector):
    connector_name = "live_json"
    source_type = "live_json"
    base_url = ""

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok", message=self.base_url)

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        if request.config.get("path") or request.params.get("path"):
            return super().fetch(request)
        url = self.build_url(request)
        try:
            raw = self.get_json(url, timeout=int(request.params.get("timeout_seconds") or request.config.get("timeout_seconds") or 30))
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"url": url}, errors=[str(exc)])
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=self.extract_items(raw), raw_text=self.extract_text(raw), metadata={"url": url, "raw_type": type(raw).__name__})

    def build_url(self, request: SourceFetchRequest) -> str:
        return self.base_url

    def get_json(self, url: str, *, timeout: int = 30) -> Any:
        req = urllib.request.Request(url, headers=self.request_headers())
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - explicit configured source
            return json.loads(resp.read().decode("utf-8"))

    def get_text(self, url: str, *, timeout: int = 30, retries: int = 3) -> str:
        import time
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                req = urllib.request.Request(url, headers={"Accept": "text/html,*/*"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - explicit configured source
                    return resp.read().decode("utf-8", errors="replace")
            except Exception as exc:
                last_exc = exc
                if attempt < retries - 1:
                    time.sleep(2)
        raise RuntimeError(f"get_text failed after {retries} retries: {last_exc}")

    def request_headers(self) -> dict[str, str]:
        return {"User-Agent": "ai4sec-platform/0.1", "Accept": "application/json"}

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
