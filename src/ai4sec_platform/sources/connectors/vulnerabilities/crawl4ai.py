from __future__ import annotations

import re
import time
import urllib.error
import urllib.request
from html import unescape
from typing import Any

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.result import SourceFetchResult


class Crawl4aiConnector:
    connector_name = "crawl4ai"
    source_type = "crawl4ai"

    def health_check(self, config: dict) -> SourceHealth:
        try:
            import crawl4ai  # noqa: F401
            return SourceHealth(status="configured", message="crawl4ai import ok")
        except Exception:
            return SourceHealth(status="degraded", message="crawl4ai not installed; urllib fallback available")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        params = request.params or {}
        candidates = params.get("candidates") or params.get("items") or []
        if not candidates and params.get("urls"):
            candidates = [{"url": url, "title": url} for url in params.get("urls")]
        if not isinstance(candidates, list):
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["invalid_candidates"])

        timeout = float(params.get("timeout") or request.config.get("timeout") or 20)
        max_items = int(params.get("max_items") or request.config.get("max_items") or len(candidates) or 0)
        use_crawl4ai = bool(params.get("use_crawl4ai", request.config.get("use_crawl4ai", False)))
        items: list[dict[str, Any]] = []
        errors: list[str] = []
        for candidate in candidates[:max_items]:
            if not isinstance(candidate, dict):
                continue
            try:
                items.append(_crawl_candidate(candidate, timeout=timeout, use_crawl4ai=use_crawl4ai))
            except Exception as exc:  # pragma: no cover - network/runtime dependent
                errors.append(f"{candidate.get('url')}: {exc}")
                items.append(_failed(candidate, str(exc)))

        return SourceFetchResult(
            source_name=request.source_name,
            connector_name=self.connector_name,
            items=items,
            metadata={"count": len(items), "use_crawl4ai": use_crawl4ai, "timeout": timeout},
            errors=errors,
        )


def _crawl_candidate(candidate: dict[str, Any], *, timeout: float, use_crawl4ai: bool) -> dict[str, Any]:
    if candidate.get("markdown") or candidate.get("cleaned_text") or candidate.get("content"):
        markdown = str(candidate.get("markdown") or candidate.get("cleaned_text") or candidate.get("content") or candidate.get("snippet") or "")
        return _success(candidate, markdown=markdown, mode="provided_content")
    if use_crawl4ai:
        try:
            return _crawl4ai_sync(candidate, timeout=timeout)
        except Exception:
            # Fallback below keeps the pipeline usable in minimal environments.
            pass
    return _urllib_crawl(candidate, timeout=timeout)


def _crawl4ai_sync(candidate: dict[str, Any], *, timeout: float) -> dict[str, Any]:  # pragma: no cover - optional dependency
    import asyncio
    from crawl4ai import AsyncWebCrawler, CrawlerRunConfig

    async def run() -> dict[str, Any]:
        config = CrawlerRunConfig(page_timeout=int(timeout * 1000), delay_before_return_html=1.0, remove_consent_popups=True)
        async with AsyncWebCrawler(verbose=False) as crawler:
            result = await crawler.arun(url=str(candidate.get("url")), config=config)
            if not getattr(result, "success", False):
                return _failed(candidate, getattr(result, "error_message", "crawl4ai failed"))
            markdown = getattr(result, "markdown", "") or ""
            return _success(candidate, markdown=markdown, mode="crawl4ai", metadata=getattr(result, "metadata", {}) or {})

    return asyncio.run(run())


def _urllib_crawl(candidate: dict[str, Any], *, timeout: float) -> dict[str, Any]:
    url = str(candidate.get("url") or "")
    if not url:
        return _failed(candidate, "missing_url")
    request = urllib.request.Request(url, headers={"User-Agent": "AI4SEC-Platform/0.1 shadow crawler"})
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - user-provided discovery URL
            raw = response.read(2_000_000)
            content_type = response.headers.get("content-type", "")
    except urllib.error.HTTPError as exc:
        return _failed(candidate, f"HTTP {exc.code}")
    html = raw.decode("utf-8", errors="replace")
    title = _title(html) or candidate.get("title") or url
    text = _html_to_text(html)
    return _success(candidate, markdown=text, title=title, mode="urllib", metadata={"content_type": content_type, "elapsed_ms": int((time.time() - started) * 1000)})


def _success(candidate: dict[str, Any], *, markdown: str, mode: str, title: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        **candidate,
        "title": title or candidate.get("title") or candidate.get("url") or "未命名页面",
        "markdown": markdown,
        "cleaned_text": candidate.get("cleaned_text") or markdown,
        "markdown_length": len(markdown),
        "content_length": len(markdown),
        "success": True,
        "crawl_mode": mode,
        "crawl_info": {"markdown_length": len(markdown), "success": True, "mode": mode, "metadata": metadata or {}},
        "metadata": metadata or {},
    }


def _failed(candidate: dict[str, Any], error: str) -> dict[str, Any]:
    return {**candidate, "success": False, "error": error, "markdown": "", "cleaned_text": "", "markdown_length": 0, "content_length": 0, "crawl_info": {"success": False, "error": error}}


def _title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return unescape(re.sub(r"\s+", " ", match.group(1)).strip()) if match else ""


def _html_to_text(html: str) -> str:
    html = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.IGNORECASE)
    html = re.sub(r"<style[\s\S]*?</style>", " ", html, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html)
    text = unescape(text)
    return re.sub(r"[ \t\r\f\v]+", " ", re.sub(r"\n\s*\n+", "\n\n", text)).strip()
