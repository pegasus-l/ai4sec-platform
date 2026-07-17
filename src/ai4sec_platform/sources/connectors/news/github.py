from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class GithubConnector(JsonFileConnector):
    connector_name = "github"
    source_type = "github"
