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
                # 2026-10-09:原先只保留 dict,把「data 是字符串数组」的接口整级丢空 ——
                # softwareCenter/getFirmwareVersion 返回的就是 ["Ascend HDK 25.5.2", "Ascend HDK 25.5.1"],
                # 被过滤成 0 条 → 固件包这一级(以及嵌在它里面的固件资源级)永远采不到。
                # SourceFetchResult.items 的契约是 dict 列表,所以标量要包一层;
                # 本网关目前只有这一个接口返回字符串数组(即固件版本号),故用 firmwareVersion 作键。
                return [
                    item if isinstance(item, dict) else {"firmwareVersion": str(item)}
                    for item in data
                    if isinstance(item, (dict, str))
                ]
            if isinstance(data, dict):
                for key in ["list", "items", "records", "repositories", "tags"]:
                    value = data.get(key)
                    if isinstance(value, list):
                        return [item for item in value if isinstance(item, dict)]
                return [data]
        return super().extract_items(raw)
