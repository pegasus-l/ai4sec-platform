from __future__ import annotations

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector, with_query


class HuaweiMirrorConnector(LiveJsonConnector):
    connector_name = "huawei_mirror"
    source_type = "huawei_mirror_api"
    base_url = "https://mirrors.huaweicloud.com/api/v1/repositories"

    def build_url(self, request: SourceFetchRequest) -> str:
        return with_query(self.base_url, {"catalog": request.params.get("catalog") or request.config.get("catalog") or ""})
