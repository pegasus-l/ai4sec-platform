from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class AnysearchConnector(JsonFileConnector):
    connector_name = "anysearch"
    source_type = "anysearch"
