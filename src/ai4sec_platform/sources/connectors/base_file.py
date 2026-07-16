from __future__ import annotations

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.result import SourceFetchResult


class PlaceholderConnector:
    connector_name = "placeholder"
    source_type = "placeholder"

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="not_configured", message="Connector skeleton is present; implementation pending.")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"status": "not_implemented"})
