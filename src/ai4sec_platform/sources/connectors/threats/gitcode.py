from __future__ import annotations

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
        """Override to add pagination for 'repos' resource — fetch ALL pages for each org."""
        resource = request.params.get("resource") or request.config.get("resource") or "repos"
        if resource != "repos":
            return super().fetch(request)

        org = request.params.get("org") or request.config.get("org") or "openharmony"
        per_page = int(request.params.get("per_page") or 100)
        timeout = int(request.params.get("timeout_seconds") or 30)
        all_items: list[dict[str, Any]] = []
        page = 1
        errors: list[str] = []

        while True:
            url = with_query(f"{self.api_base}/orgs/{org}/repos", {"type": "all", "page": page, "per_page": per_page})
            try:
                raw = self.get_json(url, timeout=timeout)
                items = self.extract_items(raw)
                if not items:
                    break
                all_items.extend(items)
                if len(items) < per_page:
                    break  # last page
                page += 1
                if page > 200:  # safety limit
                    break
            except Exception as exc:
                errors.append(f"page {page}: {exc}")
                break

        return SourceFetchResult(
            source_name=request.source_name,
            connector_name=self.connector_name,
            items=all_items,
            metadata={"url": f"{self.api_base}/orgs/{org}/repos", "org": org, "pages": page, "total": len(all_items)},
            errors=errors,
        )
