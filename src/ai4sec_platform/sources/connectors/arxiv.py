from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import PlaceholderConnector


class ArxivConnector(PlaceholderConnector):
    connector_name = "arxiv"
    source_type = "arxiv"
