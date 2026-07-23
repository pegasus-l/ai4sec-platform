from __future__ import annotations

import urllib.request

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class NewsLiveConnector(JsonFileConnector):
    def has_local_path(self, request: SourceFetchRequest) -> bool:
        return bool(request.config.get("path") or request.params.get("path"))

    def get_bytes(self, url: str, *, timeout: int = 30, headers: dict[str, str] | None = None) -> bytes:
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "ai4sec-platform/0.1", **(headers or {})},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - configured trusted sources
            return response.read()
