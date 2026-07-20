from __future__ import annotations

import re
from urllib.parse import urljoin

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector
from ai4sec_platform.sources.result import SourceFetchResult


class OpenXHuaweiConnector(LiveJsonConnector):
    connector_name = "openx_huawei"
    source_type = "openx_huawei_listing"
    base_url = "https://arquivos.openx.com.br/Huawei/"

    def build_url(self, request: SourceFetchRequest) -> str:
        return request.params.get("url") or request.config.get("url") or self.base_url

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        url = self.build_url(request)
        try:
            html = self.get_text(url, timeout=int(request.params.get("timeout_seconds") or 30))
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"url": url}, errors=[str(exc)])
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=_parse_listing(html, url), raw_text=html, metadata={"url": url, "raw_type": "html"})


def _parse_listing(html: str, base_url: str) -> list[dict]:
    items = []
    for href, text in re.findall(r'<a\s+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html or "", flags=re.I | re.S):
        label = re.sub(r"<[^>]+>", "", text).strip() or href.strip("/")
        if not label or label in {"../", "Parent Directory"} or href.startswith("?"):
            continue
        full_url = urljoin(base_url, href)
        items.append({"name": label.rstrip("/"), "url": full_url, "is_dir": href.endswith("/"), "source_type": "openx_huawei"})
    return items
