from __future__ import annotations

import json
import base64
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.base_file import JsonFileConnector
from ai4sec_platform.sources.result import SourceFetchResult


class LiveJsonConnector(JsonFileConnector):
    connector_name = "live_json"
    source_type = "live_json"
    base_url = ""
    # 值得退避重试的 HTTP 状态:限流/鉴权抖动/网关临时故障。400/404 是「真的没有」,重试没有意义。
    RETRY_STATUS = frozenset({401, 403, 408, 425, 429, 500, 502, 503, 504})

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok", message=self.base_url)

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        # 2026-10-09:带 resource 的请求一定是打活接口,不能走下面这个「本地 JSON 快照」分支。
        # 目录遍历和抓正文这两个调用(gitcode/atomgit 的 contents、file 资源)是用 params["path"]
        # 传**仓库内路径**的,原来一律被当成「读本地文件」→ 除根目录列表(path="")外全部返回
        # missing_path,安全仓的公告正文因此一条都采不到(BFS 永远停在根目录)。
        # 真正的本地快照模式(source_records_path / resume_from_run_id)不走连接器 fetch,
        # 见 domains/threats/adapters/huawei_sources.py:_load_source_records_from_path。
        if not request.params.get("resource") and (request.config.get("path") or request.params.get("path")):
            return super().fetch(request)
        url = self.build_url(request)
        try:
            raw = self.get_json(url, timeout=int(request.params.get("timeout_seconds") or request.config.get("timeout_seconds") or 30))
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"url": url}, errors=[str(exc)])
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=self.extract_items(raw), raw_text=self.extract_text(raw), metadata={"url": url, "raw_type": type(raw).__name__})

    def build_url(self, request: SourceFetchRequest) -> str:
        return self.base_url

    def get_json(self, url: str, *, timeout: int = 30, attempts: int = 3) -> Any:
        # 2026-10-09:活接口统一加退避重试。GitCode/AtomGit 的 contents(列目录)与 file(取正文)
        # 这两个资源原先一次都不重试,而它们对连续请求会间歇返 401(实测同一个 URL 成功/401 交替);
        # 目录遍历只要丢一个目录,上游 _discover_security_file_paths 就少一片候选,正文一条都拿不回来
        # (实测 opengauss/security 发现 5 个候选、抓回 0 篇)。明确「不存在」的 400/404 不重试,
        # 重试只会白等;401/403/408/425/429 与 5xx、以及网络层异常退避后重试。
        total = max(1, attempts)
        last_exc: Exception | None = None
        for attempt in range(total):
            try:
                req = urllib.request.Request(url, headers=self.request_headers())
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - explicit configured source
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                last_exc = exc
                if exc.code not in self.RETRY_STATUS or attempt >= total - 1:
                    raise
            except Exception as exc:  # noqa: BLE001 - 网络层/超时/解码失败都退避重试
                last_exc = exc
                if attempt >= total - 1:
                    raise
            time.sleep(self._retry_delay(attempt, last_exc))
        raise last_exc  # pragma: no cover - 循环内必然 return 或 raise

    def _retry_delay(self, attempt: int, exc: Exception | None) -> float:
        """限流/鉴权类错误退避更久(实测 401 要等几秒才恢复),其余 1s/3s。"""
        code = getattr(exc, "code", None)
        base = 5.0 if code in {401, 403, 429} else 1.0
        return base * (3**attempt)

    def get_text(self, url: str, *, timeout: int = 30, retries: int = 3) -> str:
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        last_exc: Exception | None = None
        for attempt in range(retries):
            try:
                # 2026-10-09:原先写死 Accept,连接器自定义的 UA 传不下来(openx_huawei 站改版后需要常规 UA)。
                headers = {**self.request_headers(), "Accept": "text/html,*/*"}
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:  # noqa: S310
                    return resp.read().decode("utf-8", errors="replace")
            except Exception as exc:
                last_exc = exc
                if attempt < retries - 1:
                    time.sleep(2)
        raise RuntimeError(f"get_text failed after {retries} retries: {last_exc}")

    def request_headers(self) -> dict[str, str]:
        return {"User-Agent": "ai4sec-platform/0.1", "Accept": "application/json"}

    def extract_items(self, raw: Any) -> list[dict[str, Any]]:
        if isinstance(raw, list):
            return [item for item in raw if isinstance(item, dict)]
        if isinstance(raw, dict):
            # "tree" = git/trees 的全量文件树条目(见 huawei_sources._discover_paths_from_tree)。
            for key in ["projects", "items", "results", "data", "repositories", "list", "tree"]:
                value = raw.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
        return []

    def extract_text(self, raw: Any) -> str:
        if not isinstance(raw, dict):
            return ""
        content = raw.get("content") or ""
        if not content:
            return ""
        try:
            return base64.b64decode(content).decode("utf-8", errors="replace")
        except Exception:
            return ""


def with_query(base: str, params: dict[str, Any]) -> str:
    clean = {key: value for key, value in params.items() if value not in {None, ""}}
    return f"{base}?{urllib.parse.urlencode(clean)}" if clean else base
