"""OSV 连接器:按 id 查单条记录(CVE / GHSA / OSV 都认)。

OSV 是 P3 里**唯一**可信的补丁线索来源:NVD 的 references 实测几乎不打 `Patch`/`Fix`
标签(2026-10-16 抽样 tags 全空),而 OSV 的 `references[].type == "FIX"` 是明确的。

命中率的现实(2026-10-19 基线,近 7 天新公开的 CVE 抽样 80 条):
全量 16%、CVSS≥7 那批 24%、CVSS≥9 那批 33%。所以查不到**是常态**,不是故障 ——
调用方按 `not_found` 留痕并 7 天后复查,不重试同一个 404。
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector
from ai4sec_platform.sources.result import SourceFetchResult

DEFAULT_BASE_URL = "https://api.osv.dev/v1/vulns/"
# 按包/按 commit 查是 POST /v1/query(与按 id 查的 GET /v1/vulns/{id} 是两个端点)
QUERY_URL = "https://api.osv.dev/v1/query"


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

    # ── POST /v1/query:按包 / 按 commit ──────────────────────────────────────

    def query_package(self, name: str, ecosystem: str, *, page_token: str = "", timeout: int = 60) -> dict[str, Any]:
        """按**包**查(不传版本号 = 该包全部已知漏洞)。返回原始响应(`vulns` + `next_page_token`)。

        OSV 没有"按发布时间窗拉"的接口(见 P3 设计),所以"盯一个包"只能用这个端点把该包的
        记录翻出来,再由调用方按 `published` 过滤 —— 翻页有上限,别把一个热门包的几页全拉完。
        """
        body: dict[str, Any] = {"package": {"name": str(name).strip(), "ecosystem": str(ecosystem).strip()}}
        if page_token:
            body["page_token"] = page_token
        return self._post_json(body, timeout=timeout)

    def query_commit(self, commit: str, *, timeout: int = 45) -> dict[str, Any]:
        """按 commit 查:该提交所在版本受哪些洞影响。

        **能力边界(必须让调用方知道):** 只有漏洞记录里带 `ranges[].type == "GIT"` 时才查得到,
        实测主要是 OSS-Fuzz 的项目;普通 GitHub 仓的 GHSA/PyPI 记录多半是 ECOSYSTEM 区间,
        按 commit 查会返回空 —— 空不等于没有洞,只等于 OSV 没按 git 区间收录。
        """
        return self._post_json({"commit": str(commit).strip()}, timeout=timeout)

    def _post_json(self, body: dict[str, Any], *, timeout: int) -> dict[str, Any]:
        """POST JSON + 与 GET 相同的退避口径(RETRY_STATUS 重试,400/404 不重试)。

        400 通常是"生态名写错了"或"commit 不是 40 位" —— 重试只是白等,而且会掩盖用户输入错误,
        所以直接抛出,由采集步记进 errors。
        """
        attempts = 3
        data = json.dumps(body).encode("utf-8")
        last_exc: Exception | None = None
        for attempt in range(attempts):
            request = urllib.request.Request(
                QUERY_URL,
                data=data,
                headers={**self.request_headers(), "Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - 固定 api.osv.dev
                    payload = json.loads(response.read().decode("utf-8"))
                return payload if isinstance(payload, dict) else {}
            except urllib.error.HTTPError as exc:
                last_exc = exc
                if exc.code not in self.RETRY_STATUS or attempt >= attempts - 1:
                    raise
            except Exception as exc:  # noqa: BLE001 - 网络层/超时/解码失败都退避重试
                last_exc = exc
                if attempt >= attempts - 1:
                    raise
            time.sleep(self._retry_delay(attempt, last_exc))
        raise last_exc  # pragma: no cover - 循环内必然 return 或 raise

    def extract_items(self, raw: Any) -> list[dict[str, Any]]:
        return [raw] if isinstance(raw, dict) else []
