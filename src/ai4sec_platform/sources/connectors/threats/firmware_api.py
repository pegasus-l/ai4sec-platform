from __future__ import annotations

import time
from typing import Any

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector
from ai4sec_platform.sources.result import SourceFetchResult

BASE_API = "https://www.hiascend.com/ascendgateway/ascendservice"


class FirmwareApiConnector(LiveJsonConnector):
    """3-level HiAscend API query for firmware: products → models → packages."""

    connector_name = "firmware_api"
    source_type = "firmware_api"
    base_url = BASE_API

    def request_headers(self) -> dict[str, str]:
        return {
            "User-Agent": "Mozilla/5.0 (ai4sec-platform)",
            "Accept": "application/json",
            "Referer": "https://www.hiascend.com/hardware/firmware-drivers/community",
        }

    def build_url(self, request: SourceFetchRequest) -> str:
        return self.base_url

    def _api_get(self, endpoint: str, params: dict[str, str]) -> list[dict] | dict:
        url = f"{self.base_url}/{endpoint}"
        from urllib.parse import urlencode
        full_url = f"{url}?{urlencode(params)}"
        try:
            raw = self.get_json(full_url, timeout=30)
            if isinstance(raw, dict):
                if raw.get("success") or raw.get("code") == 200:
                    return raw.get("data", [])
            return []
        except Exception:
            return []

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        all_items: list[dict[str, Any]] = []
        timeout = int(request.params.get("timeout_seconds") or 60)
        import time as _time

        # Only community for now (commercial is too slow)
        for fw_type in ("community",):
            products = self._api_get("softwareCenter/queryResourceProductList", {"lang": "zh", "type": fw_type})
            if not isinstance(products, list):
                continue

            for prod in products:
                if not isinstance(prod, dict):
                    continue
                product_id = str(prod.get("productId", ""))
                product_name = prod.get("productName", "")

                models = self._api_get("softwareCenter/queryProductModelList", {"lang": "zh", "productId": product_id, "type": fw_type})
                if not isinstance(models, list):
                    continue

                for model in models:
                    if not isinstance(model, dict):
                        continue
                    model_id = str(model.get("modelId", ""))
                    model_name = model.get("modelName", "")

                    # Community: query CANN → firmware → resource list
                    cann_list = self._api_get("softwareCenter/getCannVersion", {"lang": "zh", "modelId": model_id, "type": fw_type})
                    if not isinstance(cann_list, list) or not cann_list:
                        continue  # skip models with no CANN versions

                    for cann in cann_list:
                        if not isinstance(cann, dict):
                            continue
                        cann_id = str(cann.get("cannId", ""))
                        cann_version = cann.get("cannVersion", "")

                        fw_list = self._api_get("softwareCenter/getFirmwareVersion", {"lang": "zh", "modelId": model_id, "cannId": cann_id, "type": fw_type})
                        if not isinstance(fw_list, list) or not fw_list:
                            continue

                        for fw in fw_list:
                            fw_name = fw if isinstance(fw, str) else (fw.get("firmwareName", "") if isinstance(fw, dict) else str(fw))

                            resources = self._api_get("softwareCenter/queryResourceCenterList", {
                                "lang": "zh", "type": fw_type, "modelId": model_id, "version": fw_name,
                                "productType": "", "cpuArchitecture": "", "softwareType": "",
                            })
                            if not isinstance(resources, list) or not resources:
                                continue

                            for item in resources:
                                if not isinstance(item, dict):
                                    continue
                                all_items.append({
                                    "source_type": fw_type,
                                    "productSeries": product_name,
                                    "productId": product_id,
                                    "productModel": model_name,
                                    "modelId": model_id,
                                    "cannVersion": cann_version,
                                    "cannId": cann_id,
                                    "firmwareVersion": fw_name,
                                    "packageName": item.get("packageName", ""),
                                    "productType": item.get("productType", ""),
                                    "releaseTime": item.get("releaseTime", ""),
                                    "softwareExplain": item.get("softwareExplain", ""),
                                    "fileSize": item.get("fileSize", ""),
                                    "downloadUrl": item.get("downloadUrl", ""),
                                    "packageId": item.get("packageId", ""),
                                })
                            _time.sleep(0.1)  # small delay between firmware versions

        return SourceFetchResult(
            source_name=request.source_name,
            connector_name=self.connector_name,
            items=all_items,
            metadata={"total": len(all_items), "types": list({i.get("source_type") for i in all_items})},
        )
