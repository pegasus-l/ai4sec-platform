from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import PlaceholderConnector


class GithubConnector(PlaceholderConnector):
    connector_name = "github"
    source_type = "github"
