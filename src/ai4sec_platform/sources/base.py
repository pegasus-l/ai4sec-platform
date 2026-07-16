from __future__ import annotations

from typing import Protocol

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.result import SourceFetchResult


class SourceConnector(Protocol):
    connector_name: str
    source_type: str

    def health_check(self, config: dict) -> SourceHealth:
        ...

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        ...
