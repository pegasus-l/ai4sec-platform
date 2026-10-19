"""OSV 连接器:按 id 查单条记录(CVE / GHSA / OSV 都认)。

OSV 是 P3 里**唯一**可信的补丁线索来源:NVD 的 references 实测几乎不打 `Patch`/`Fix`
标签(2026-10-16 抽样 tags 全空),而 OSV 的 `references[].type == "FIX"` 是明确的。

命中率的现实(2026-10-19 基线,近 7 天新公开的 CVE 抽样 80 条):
全量 16%、CVSS≥7 那批 24%、CVSS≥9 那批 33%。所以查不到**是常态**,不是故障 ——
调用方按 `not_found` 留痕并 7 天后复查,不重试同一个 404。
"""

from __future__ import annotations

import urllib.error
import urllib.parse
from typing import Any

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector
from ai4sec_platform.sources.result import SourceFetchResult

DEFAULT_BASE_URL = "https://api.osv.dev/v1/vulns/"


class OsvConnector(LiveJsonConnector):
    connector_name = "osv"
    source_type = "osv"
    base_url = DEFAULT_BASE_URL

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok", message=self.base_url + "(免 key)")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        ids = request.params.get("ids") or ([request.params["id"]] if request.params.get("id") else [])
        items: list[dict[str, Any]] = []
        errors: list[str] = []
        for vuln_id in ids:
            try:
                payload = self.lookup(str(vuln_id))
            except Exception as exc:  # noqa: BLE001 - 单条失败不该让整批失败
                errors.append(f"{vuln_id}: {exc}")
                continue
            if payload:
                items.append(payload)
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, metadata={"requested": len(list(ids))}, errors=errors)

    def lookup(self, vuln_id: str) -> dict[str, Any] | None:
        """查一条。**404 返回 None**(OSV 没有这条),其余错误照常抛出让调用方记账。"""
        url = self.base_url + urllib.parse.quote(str(vuln_id).strip())
        try:
            payload = self.get_json(url, timeout=45, attempts=3)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        return payload if isinstance(payload, dict) else None

    def extract_items(self, raw: Any) -> list[dict[str, Any]]:
        return [raw] if isinstance(raw, dict) else []
