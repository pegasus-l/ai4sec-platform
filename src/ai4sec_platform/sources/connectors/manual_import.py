from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import PlaceholderConnector


class ManualImportConnector(PlaceholderConnector):
    connector_name = "manual_import"
    source_type = "manual_import"
