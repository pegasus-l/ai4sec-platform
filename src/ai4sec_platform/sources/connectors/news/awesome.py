from __future__ import annotations

import base64
import json
import os

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.news.base_live import NewsLiveConnector
from ai4sec_platform.sources.result import SourceFetchResult


class AwesomeConnector(NewsLiveConnector):
    connector_name = "awesome"
    source_type = "discovery"

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok" if config.get("repositories") else "missing", message=f"{len(config.get('repositories') or [])} repositories")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        if self.has_local_path(request):
            return super().fetch(request)
        token = os.getenv("GITHUB_TOKEN", "")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        items: list[dict] = []
        errors: list[str] = []
        for repository in request.config.get("repositories") or []:
            url = f"https://api.github.com/repos/{repository}/readme"
            try:
                raw = json.loads(self.get_bytes(url, headers=headers).decode("utf-8"))
                content = base64.b64decode(raw.get("content") or "").decode("utf-8", errors="replace")
                items.append({"id": f"awesome:{repository}", "title": str(repository), "url": f"https://github.com/{repository}", "text": content, "source": "awesome"})
            except Exception as exc:
                errors.append(f"{repository}: {exc}")
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, metadata={"repositories": request.config.get("repositories") or []}, errors=errors)
