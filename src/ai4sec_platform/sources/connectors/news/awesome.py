from __future__ import annotations

import base64
import json
import os
import re
import urllib.parse

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.news.base_live import NewsLiveConnector, retry_kwargs
from ai4sec_platform.sources.result import SourceFetchResult


class AwesomeConnector(NewsLiveConnector):
    connector_name = "awesome"
    source_type = "discovery"

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok" if config.get("repositories") else "missing", message=f"{len(config.get('repositories') or [])} repositories")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        token = os.getenv("GITHUB_TOKEN", "")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        items: list[dict] = []
        errors: list[str] = []
        metadata: list[dict] = []
        timeout = int(request.params.get("timeout_seconds") or 30)
        for repository in request.config.get("repositories") or []:
            url = f"https://api.github.com/repos/{repository}/readme"
            try:
                raw = json.loads(self.get_bytes(url, timeout=timeout, headers=headers, **retry_kwargs(request)).decode("utf-8"))
                content = base64.b64decode(raw.get("content") or "").decode("utf-8", errors="replace")
                items.append({"id": f"awesome:{repository}", "title": str(repository), "url": f"https://github.com/{repository}", "text": content, "source": "awesome"})
                subpages = _recent_subpages(content, str(repository), request.config)
                loaded_subpages = 0
                for path in subpages:
                    try:
                        page_url = f"https://api.github.com/repos/{repository}/contents/{urllib.parse.quote(path, safe='/')}"
                        page_raw = json.loads(self.get_bytes(page_url, timeout=timeout, headers=headers, **retry_kwargs(request)).decode("utf-8"))
                        page_content = base64.b64decode(page_raw.get("content") or "").decode("utf-8", errors="replace")
                        items.append({"id": f"awesome:{repository}:{path}", "title": f"{repository} / {path}", "url": f"https://github.com/{repository}/blob/main/{path}", "text": page_content, "source": "awesome"})
                        loaded_subpages += 1
                    except Exception as exc:
                        errors.append(f"{repository}:{path}: {exc}")
                metadata.append({"repository": repository, "subpages_discovered": len(subpages), "subpages_loaded": loaded_subpages})
            except Exception as exc:
                errors.append(f"{repository}: {exc}")
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, metadata={"repositories": metadata}, errors=errors)


def _recent_subpages(content: str, repository: str, config: dict) -> list[str]:
    years = {str(year) for year in config.get("recent_subpage_years") or [2026, 2025]}
    max_subpages = int(config.get("max_subpages") or 4)
    paths: list[str] = []
    seen: set[str] = set()
    for target in re.findall(r"\[[^\]]+\]\(([^)]+\.md(?:#[^)]*)?)\)", content, flags=re.I):
        clean_target = target.split("#", 1)[0]
        marker = f"github.com/{repository}/blob/main/"
        path = clean_target.split(marker, 1)[1] if marker in clean_target else clean_target.lstrip("./")
        if "Research_Papers" not in path or not any(year in path for year in years) or path in seen:
            continue
        seen.add(path)
        paths.append(path)
        if len(paths) >= max_subpages:
            break
    return paths
