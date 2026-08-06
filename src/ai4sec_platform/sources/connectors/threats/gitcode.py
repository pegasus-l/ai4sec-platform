from __future__ import annotations

import time
import urllib.error
import urllib.request
from typing import Any

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector, with_query
from ai4sec_platform.sources.result import SourceFetchResult


class GitCodeConnector(LiveJsonConnector):
    connector_name = "gitcode"
    source_type = "gitcode_api"
    api_base = "https://api.gitcode.com/api/v5"
    base_url = api_base

    def build_url(self, request: SourceFetchRequest) -> str:
        resource = request.params.get("resource") or request.config.get("resource") or "repos"
        org = request.params.get("org") or request.config.get("org") or "openharmony"
        owner = request.params.get("owner") or request.config.get("owner") or org
        repo = request.params.get("repo") or request.config.get("repo") or ""
        path = request.params.get("path") or request.config.get("path") or ""
        page = request.params.get("page") or 1
        per_page = request.params.get("per_page") or 100
        if resource == "repos":
            return with_query(f"{self.api_base}/orgs/{org}/repos", {"type": "all", "page": page, "per_page": per_page})
        if resource == "issues":
            return with_query(f"{self.api_base}/repos/{owner}/{repo}/issues", {"state": "all", "page": page, "per_page": per_page})
        if resource in {"pull_requests", "prs"}:
            return with_query(f"{self.api_base}/repos/{owner}/{repo}/pull_requests", {"state": "all", "page": page, "per_page": per_page})
        if resource == "contents":
            suffix = f"/{path}" if path else ""
            return f"{self.api_base}/repos/{owner}/{repo}/contents{suffix}"
        if resource == "file":
            return f"{self.api_base}/repos/{owner}/{repo}/contents/{path}"
        return super().build_url(request)

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        """Override to add pagination with rate-limit handling for 'repos' resource."""
        resource = request.params.get("resource") or request.config.get("resource") or "repos"
        if resource != "repos":
            return super().fetch(request)

        org = request.params.get("org") or request.config.get("org") or "openharmony"
        per_page = int(request.params.get("per_page") or 100)
        timeout = int(request.params.get("timeout_seconds") or 60)
        max_pages = int(request.params.get("max_pages") or 1)
        max_retries = 3
        rate_limit_sleep = 30
        page_delay = 1  # sleep between successful pages to avoid triggering rate limits

        all_items: list[dict[str, Any]] = []
        errors: list[str] = []
        truncated = False

        for page in range(1, max_pages + 1):
            url = with_query(f"{self.api_base}/orgs/{org}/repos", {"type": "all", "page": page, "per_page": per_page})
            success = False

            for retry in range(max_retries):
                try:
                    req = urllib.request.Request(url, headers={
                        "Accept": "application/json",
                    })
                    resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310
                    raw = resp.read()
                    import json
                    data = json.loads(raw)
                    success = True
                    break
                except urllib.error.HTTPError as e:
                    if e.code in (403, 429) and retry < max_retries - 1:
                        time.sleep(rate_limit_sleep)
                        continue
                    else:
                        errors.append(f"page {page} HTTP {e.code}: {e.reason}")
                        break
                except Exception as e:
                    if retry < max_retries - 1:
                        time.sleep(5)
                        continue
                    else:
                        errors.append(f"page {page}: {e}")
                        break

            if not success:
                errors.append(f"page {page} stopped after {max_retries} retries")
                break

            items = self.extract_items(data) if 'data' in dir() else []
            if not items:
                break  # no more data — normal end of pagination

            all_items.extend(items)
            if len(items) < per_page:
                break  # last page
            if page == max_pages:
                truncated = True
                errors.append(f"pagination limit reached at page {max_pages} with a full page of {per_page} items")
                break

            time.sleep(page_delay)  # small delay between pages to avoid rate limiting

        return SourceFetchResult(
            source_name=request.source_name,
            connector_name=self.connector_name,
            items=all_items,
            metadata={"url": f"{self.api_base}/orgs/{org}/repos", "org": org, "pages": page, "total": len(all_items), "truncated": truncated},
            errors=errors,
        )
