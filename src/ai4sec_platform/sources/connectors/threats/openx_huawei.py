from __future__ import annotations

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector


class OpenXHuaweiConnector(LiveJsonConnector):
    connector_name = "openx_huawei"
    source_type = "openx_huawei_listing"
    base_url = "https://arquivos.openx.com.br/Huawei/"

    def build_url(self, request: SourceFetchRequest) -> str:
        return request.params.get("url") or request.config.get("url") or self.base_url
