from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class AwesomeConnector(JsonFileConnector):
    connector_name = "awesome"
    source_type = "awesome"
