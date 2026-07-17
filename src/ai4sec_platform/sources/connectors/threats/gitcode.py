from __future__ import annotations

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector, with_query


class GitCodeConnector(LiveJsonConnector):
    connector_name = "gitcode"
    source_type = "gitcode_repo_api"
    base_url = "https://api.gitcode.com/api/v5/orgs/{org}/repos"

    def build_url(self, request: SourceFetchRequest) -> str:
        org = request.params.get("org") or request.config.get("org") or "openharmony"
        page = request.params.get("page") or 1
        per_page = request.params.get("per_page") or 100
        return with_query(self.base_url.format(org=org), {"type": "all", "page": page, "per_page": per_page})
