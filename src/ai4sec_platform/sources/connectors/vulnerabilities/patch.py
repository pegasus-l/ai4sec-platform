"""补丁下载:把 github / gitlab 的 commit、PR 链接换成 `.patch` 文本。

单独一个连接器而不是复用 `LiveJsonConnector.get_text`,原因是后者**关掉了 TLS 校验**
(它服务的是一批证书常年不对的老站)。补丁是从 github 拉的可执行上下文,不该继承那个放松。
"""

from __future__ import annotations

import urllib.request

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.result import SourceFetchResult

# 单个补丁的读取上限。正常的漏洞修复 diff 是 KB 级;超过 1 MB 的多半是依赖锁文件或整仓重构,
# 存进上下文表既没有信息量又占空间。
MAX_BYTES = 1024 * 1024
USER_AGENT = "ai4sec-platform/0.1 (+vulnerability-case-context)"


class PatchConnector:
    connector_name = "patch"
    source_type = "patch"

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok", message="github/gitlab .patch")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        url = str(request.params.get("url") or "")
        if not url:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["missing_url"])
        try:
            text = self.fetch_diff(url)
        except Exception as exc:  # noqa: BLE001
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=[str(exc)])
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=[{"url": url, "diff": text}], metadata={"bytes": len(text)})

    def fetch_diff(self, url: str, *, timeout: int = 45) -> str:
        """取 `.patch` 原文。非 2xx 直接抛,由调用方记成 not_found / error。"""
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/plain,*/*"})
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - 只接受 github/gitlab 的 .patch
            raw = response.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raw = raw[:MAX_BYTES]
        return raw.decode("utf-8", errors="replace")
