from __future__ import annotations

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector, with_query


class HiAscendConnector(LiveJsonConnector):
    connector_name = "hiascend"
    source_type = "hiascend_api"
    base_url = "https://www.hiascend.com/ascendgateway/ascendservice"

    def request_headers(self) -> dict[str, str]:
        return {
            "User-Agent": "Mozilla/5.0 (ai4sec-platform)",
            "Accept": "application/json",
            "Referer": "https://www.hiascend.com/hardware/firmware-drivers/community",
        }

    def build_url(self, request: SourceFetchRequest) -> str:
        endpoint = request.params.get("endpoint") or request.config.get("endpoint") or "softwareCenter/queryResourceProductList"
        params = {key: value for key, value in request.params.items() if key != "endpoint"}
        return with_query(f"{self.base_url}/{endpoint}", params)

    def extract_items(self, raw):
        if isinstance(raw, dict):
            data = raw.get("data")
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
            if isinstance(data, dict):
                for key in ["list", "items", "records", "repositories", "tags"]:
                    value = data.get(key)
                    if isinstance(value, list):
                        return [item for item in value if isinstance(item, dict)]
                return [data]
        return super().extract_items(raw)
