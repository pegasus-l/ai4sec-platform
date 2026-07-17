from __future__ import annotations

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector, with_query


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
        if resource == "contents":
            suffix = f"/{path}" if path else ""
            return f"{self.api_base}/repos/{owner}/{repo}/contents{suffix}"
        if resource == "file":
            return f"{self.api_base}/repos/{owner}/{repo}/contents/{path}"
        return super().build_url(request)
