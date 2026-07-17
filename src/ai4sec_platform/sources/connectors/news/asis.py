from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class AsisConnector(JsonFileConnector):
    connector_name = "asis"
    source_type = "asis"
