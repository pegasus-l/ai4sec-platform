"""NVD 2.0 连接器:按**发布时间窗**取新公开的 CVE。

为什么只有 NVD 能当"每日新增"的入口:OSV **没有**时间窗参数(只能按包/生态或按 id 查,
2026-10-16 实测),能回答"某段时间内新公开了哪些洞"的公开源只有 NVD。

限速:无 API key 时 5 请求/30 秒。一页 2000 条,近 7 天实测 5496 条 ⇒ 3 页,
翻页间隔 7 秒。这个间隔是刻意的 —— 打满限速会换来 403,而 `LiveJsonConnector.get_json`
对 403 的退避是 5s/15s/45s,比老老实实排队慢得多。
"""

from __future__ import annotations

import time
import urllib.parse
from typing import Any

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector
from ai4sec_platform.sources.result import SourceFetchResult

DEFAULT_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NvdConnector(LiveJsonConnector):
    connector_name = "nvd"
    source_type = "nvd"
    base_url = DEFAULT_BASE_URL
    # 一页 2000 条时单次响应可达 10 MB 上下, 2026-10-20/21/22 连续三晚在这一步
    # `IncompleteRead`(连接提前关闭, 3 次重试全中同一种截断), 整个采集跑批因此失败。
    # 降到 1000 条: 单页体积减半, 代价是页数翻倍(每页间隔 7s, 30 天回溯多约 2 分钟)。
    page_size = 1000
    page_interval_seconds = 7.0
    # 大响应重试要更宽容: 默认 3 次在"每次都读到一半断开"的情况下不够。
    page_attempts = 5

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        start = str(request.params.get("pub_start_date") or request.config.get("pub_start_date") or "")
        end = str(request.params.get("pub_end_date") or request.config.get("pub_end_date") or "")
        if not start or not end:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["missing_pub_window"])
        max_items = int(request.params.get("max_items") or 0)
        items = self.fetch_window(start, end, max_items=max_items)
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, metadata={"pub_start_date": start, "pub_end_date": end, "count": len(items)})

    def fetch_window(self, start: str, end: str, *, max_items: int = 0) -> list[dict[str, Any]]:
        """按 `pubStartDate`/`pubEndDate` 翻页取完一个窗口。时间串形如 `2026-10-12T00:00:00.000`(UTC)。"""
        return self._paginate({"pubStartDate": start, "pubEndDate": end}, max_items=max_items)

    def fetch_modified(self, start: str, end: str, *, max_items: int = 0) -> list[dict[str, Any]]:
        """按 `lastModStartDate`/`lastModEndDate` 取**被改过**的 CVE —— 回溯步用它捡"后补的分"。

        不能用 pub 窗口代替:一个洞的分数可能在公开后几周才由 NVD/CNA 补上,那时它的
        published 早就在窗口外了,只有 lastModified 还指着它。
        """
        return self._paginate({"lastModStartDate": start, "lastModEndDate": end}, max_items=max_items)

    def fetch_by_id(self, cve_id: str) -> dict[str, Any] | None:
        """按单个 id 查(人工添加的"按 ID 自动抓"走这条路)。NVD 没有这条时返回 None。"""
        url = f"{self.base_url}?cveId={urllib.parse.quote(str(cve_id).strip().upper())}"
        page = self.get_json(url, timeout=60)
        if not isinstance(page, dict):
            return None
        batch = page.get("vulnerabilities") or []
        return batch[0] if batch else None

    def _paginate(self, range_params: dict[str, str], *, max_items: int = 0) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        index = 0
        first = True
        while True:
            if not first:
                time.sleep(self.page_interval_seconds)
            first = False
            page = self.get_json(self._url(range_params, index), timeout=120, attempts=self.page_attempts)
            if not isinstance(page, dict):
                break
            batch = page.get("vulnerabilities") or []
            items.extend([item for item in batch if isinstance(item, dict)])
            total = int(page.get("totalResults") or 0)
            index += self.page_size
            if index >= total or not batch:
                break
            if max_items and len(items) >= max_items:
                break
        return items

    def _url(self, range_params: dict[str, str], index: int) -> str:
        # 手拼而不用 urlencode:它会把 `2026-10-12T00:00:00.000` 的冒号转成 %3A。
        # 基线跑的时候用的是原样冒号(2026-10-19 实测 200),这里保持一致,少一个变量。
        pairs = "&".join(f"{key}={value}" for key, value in range_params.items())
        return f"{self.base_url}?{pairs}&resultsPerPage={self.page_size}&startIndex={index}"

    def extract_items(self, raw: Any) -> list[dict[str, Any]]:
        # NVD 的批次键叫 `vulnerabilities`,不在基类的候选键里
        if isinstance(raw, dict):
            batch = raw.get("vulnerabilities")
            if isinstance(batch, list):
                return [item for item in batch if isinstance(item, dict)]
        return super().extract_items(raw)
