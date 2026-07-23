from __future__ import annotations

import json
import os
import urllib.parse

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.news.base_live import NewsLiveConnector
from ai4sec_platform.sources.result import SourceFetchResult


class GithubConnector(NewsLiveConnector):
    connector_name = "github"
    source_type = "project"
    api_url = "https://api.github.com/search/repositories"

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok", message=self.api_url)

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        if self.has_local_path(request):
            return super().fetch(request)
        query = str(request.params.get("query") or request.config.get("query") or "AI security")
        per_page = min(100, int(request.params.get("max_results") or request.config.get("max_results") or 30))
        url = f"{self.api_url}?{urllib.parse.urlencode({'q': query, 'sort': 'updated', 'order': 'desc', 'per_page': per_page})}"
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = os.getenv("GITHUB_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            raw_text = self.get_bytes(url, timeout=int(request.params.get("timeout_seconds") or 30), headers=headers).decode("utf-8")
            raw = json.loads(raw_text)
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=[item for item in raw.get("items", []) if isinstance(item, dict)], raw_text=raw_text, metadata={"url": url, "query": query, "total_count": raw.get("total_count", 0)})
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"url": url, "query": query}, errors=[str(exc)])
