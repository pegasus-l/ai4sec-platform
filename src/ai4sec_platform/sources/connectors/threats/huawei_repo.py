from __future__ import annotations

from ai4sec_platform.sources.connectors.base_file import JsonFileConnector


class HuaweiRepoConnector(JsonFileConnector):
    connector_name = "huawei_repo"
    source_type = "huawei_repo"
