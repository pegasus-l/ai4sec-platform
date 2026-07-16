from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import PlaceholderConnector


class RssConnector(PlaceholderConnector):
    connector_name = "rss"
    source_type = "rss"
