from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import PlaceholderConnector


class FirmwareConnector(PlaceholderConnector):
    connector_name = "firmware"
    source_type = "firmware"
