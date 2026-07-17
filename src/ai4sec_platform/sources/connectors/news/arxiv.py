from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class ArxivConnector(JsonFileConnector):
    connector_name = "arxiv"
    source_type = "arxiv"
