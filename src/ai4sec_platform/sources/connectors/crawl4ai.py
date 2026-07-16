from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class Crawl4aiConnector(JsonFileConnector):
    connector_name = "crawl4ai"
    source_type = "crawl4ai"
