from __future__ import annotations

import base64
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
        query = str(request.params.get("query") or request.config.get("query") or "AI security")
        per_page = min(100, int(request.params.get("max_results") or request.config.get("max_results") or 30))
        max_pages = max(1, min(10, int(request.params.get("max_pages") or 1)))
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = os.getenv("GITHUB_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        items: list[dict] = []
        raw_pages: list[str] = []
        total_count = 0
        last_url = ""
        try:
            for page in range(1, max_pages + 1):
                last_url = f"{self.api_url}?{urllib.parse.urlencode({'q': query, 'sort': 'updated', 'order': 'desc', 'per_page': per_page, 'page': page})}"
                raw_text = self.get_bytes(last_url, timeout=int(request.params.get("timeout_seconds") or 30), headers=headers).decode("utf-8")
                raw_pages.append(raw_text)
                raw = json.loads(raw_text)
                total_count = int(raw.get("total_count") or total_count)
                page_items = [item for item in raw.get("items", []) if isinstance(item, dict)]
                items.extend(page_items)
                if len(page_items) < per_page:
                    break
            readme_limit = min(len(items), int(request.config.get("readme_limit") or 0))
            for item in items[:readme_limit]:
                full_name = item.get("full_name")
                if not full_name:
                    continue
                try:
                    readme_raw = json.loads(self.get_bytes(f"https://api.github.com/repos/{full_name}/readme", timeout=int(request.params.get("timeout_seconds") or 30), headers=headers).decode("utf-8"))
                    item["readme_text"] = base64.b64decode(readme_raw.get("content") or "").decode("utf-8", errors="replace")[:30000]
                except Exception:
                    item["readme_text"] = ""
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, raw_text="\n".join(raw_pages), metadata={"url": last_url, "query": query, "channel": request.params.get("channel", ""), "total_count": total_count, "pages_fetched": len(raw_pages), "readmes_loaded": sum(bool(item.get("readme_text")) for item in items)})
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, raw_text="\n".join(raw_pages), metadata={"url": last_url, "query": query, "channel": request.params.get("channel", ""), "pages_fetched": len(raw_pages)}, errors=[str(exc)])
