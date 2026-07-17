from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class XFeedConnector(JsonFileConnector):
    connector_name = "x_feed"
    source_type = "x_feed"
