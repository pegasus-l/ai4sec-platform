from __future__ import annotations

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector, with_query


class HiAscendConnector(LiveJsonConnector):
    connector_name = "hiascend"
    source_type = "hiascend_api"
    base_url = "https://www.hiascend.com/ascendgateway/ascendservice"

    def build_url(self, request: SourceFetchRequest) -> str:
        endpoint = request.params.get("endpoint") or request.config.get("endpoint") or "softwareCenter/queryResourceProductList"
        params = {key: value for key, value in request.params.items() if key != "endpoint"}
        return with_query(f"{self.base_url}/{endpoint}", params)
