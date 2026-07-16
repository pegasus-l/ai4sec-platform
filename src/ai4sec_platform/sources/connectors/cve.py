from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import PlaceholderConnector


class CveConnector(PlaceholderConnector):
    connector_name = "cve"
    source_type = "cve"
