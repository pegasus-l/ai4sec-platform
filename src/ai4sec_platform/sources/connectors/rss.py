from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class RssConnector(JsonFileConnector):
    connector_name = "rss"
    source_type = "rss"
