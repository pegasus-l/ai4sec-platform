from __future__ import annotations

from ai4sec_platform.sources.connectors.threats.gitcode import GitCodeConnector


class AtomGitConnector(GitCodeConnector):
    """AtomGit uses the same API v5 structure as GitCode — inherits pagination logic."""
    connector_name = "atomgit"
    source_type = "atomgit_api"
    api_base = "https://api.atomgit.com/api/v5"
    base_url = api_base
