from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class MirrorConnector(JsonFileConnector):
    connector_name = "mirror"
    source_type = "mirror"
