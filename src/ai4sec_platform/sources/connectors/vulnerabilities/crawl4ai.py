from __future__ import annotations

import asyncio
import inspect
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from typing import Any, Callable

from ai4sec_platform.domains.vulnerabilities.crawl_policies import VulnerabilityCrawlPolicy
from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.result import SourceFetchResult


class Crawl4aiConnector:
    connector_name = "crawl4ai"
    source_type = "crawl4ai"

    def health_check(self, config: dict) -> SourceHealth:
        try:
            from crawl4ai.__version__ import __version__

            return SourceHealth(status="configured", message=f"crawl4ai {__version__} import ok")
        except Exception as exc:
            return SourceHealth(status="degraded", message=f"crawl4ai unavailable ({exc}); urllib fallback available")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        params = request.params or {}
        candidates = params.get("candidates") or params.get("items") or []
        if not candidates and params.get("urls"):
            candidates = [{"url": url, "title": url} for url in params.get("urls")]
        if not isinstance(candidates, list):
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["invalid_candidates"])

        policy = VulnerabilityCrawlPolicy.from_params(params, request.config or {})
        max_items = int(params.get("max_items") or request.config.get("max_items") or len(candidates) or 0)
        max_concurrency = _bounded_int(params.get("crawl_max_concurrency"), 10, maximum=10)
        on_item = params.get("on_crawl_item")
        items: list[dict[str, Any]] = []
        errors: list[str] = []
        seen_urls: set[str] = set()
        selected: list[dict[str, Any]] = []
        for candidate in candidates:
            if len(selected) >= max_items:
                break
            if not isinstance(candidate, dict):
                continue
            url = str(candidate.get("url") or "").strip()
            if url and url in seen_urls:
                continue
            seen_urls.add(url)
            selected.append(candidate)

        prefer_url_fetch = bool(params.get("prefer_url_fetch", False))
        with ThreadPoolExecutor(max_workers=min(max_concurrency, len(selected) or 1)) as executor:
            futures = {executor.submit(_crawl_candidate, candidate, policy=policy, prefer_url_fetch=prefer_url_fetch): candidate for candidate in selected}
            for future in as_completed(futures):
                candidate = futures[future]
                try:
                    item = future.result()
                except Exception as exc:  # pragma: no cover - defensive worker isolation
                    item = _failed(candidate, f"{type(exc).__name__}: {exc}", failure_reason="crawl_worker_error")
                items.append(item)
                if callable(on_item):
                    on_item(item, len(items), len(selected))
                if not item.get("success"):
                    errors.append(f"{item.get('url')}: {item.get('failure_reason') or item.get('error')}")

        return SourceFetchResult(
            source_name=request.source_name,
            connector_name=self.connector_name,
            items=items,
            metadata={
                "count": len(items),
                "success_count": sum(1 for item in items if item.get("success")),
                "use_crawl4ai": policy.use_crawl4ai,
                "timeout": policy.timeout_seconds,
                "max_retries": policy.max_retries,
                "max_concurrency": max_concurrency,
                "deduplicated": len(candidates[:max_items]) - len(selected),
            },
            errors=errors,
        )


def _crawl_candidate(candidate: dict[str, Any], *, policy: VulnerabilityCrawlPolicy, prefer_url_fetch: bool) -> dict[str, Any]:
    if not prefer_url_fetch and (candidate.get("markdown") or candidate.get("cleaned_text") or candidate.get("content")):
        markdown = str(candidate.get("markdown") or candidate.get("cleaned_text") or candidate.get("content") or candidate.get("snippet") or "")
        return _success(candidate, markdown=markdown, mode="provided_content", attempt_count=0)

    url = str(candidate.get("url") or "").strip()
    validation_error = policy.validate_url(url)
    if validation_error:
        return _failed(candidate, validation_error, failure_reason=validation_error, attempt_count=0)
    strategy, effective_policy = policy.for_url(url)

    crawl4ai_error = ""
    if effective_policy.use_crawl4ai:
        result, crawl4ai_error = _with_retries(lambda: _crawl4ai_sync(candidate, policy=effective_policy), effective_policy)
        if result and result.get("success"):
            return _record_strategy(result, strategy, effective_policy)
        if not effective_policy.allow_urllib_fallback:
            return _record_strategy(result or _failed(candidate, crawl4ai_error, failure_reason="crawl4ai_failed"), strategy, effective_policy)

    result, urllib_error = _with_retries(lambda: _urllib_crawl(candidate, policy=effective_policy), effective_policy)
    if result and result.get("success"):
        if crawl4ai_error:
            result["crawl_info"]["fallback_reason"] = crawl4ai_error
        return _record_strategy(result, strategy, effective_policy)
    error = urllib_error or crawl4ai_error or "crawl_failed"
    return _record_strategy(result or _failed(candidate, error, failure_reason="all_crawlers_failed"), strategy, effective_policy)


def _with_retries(operation: Callable[[], dict[str, Any]], policy: VulnerabilityCrawlPolicy) -> tuple[dict[str, Any] | None, str]:
    last_result: dict[str, Any] | None = None
    last_error = ""
    for attempt in range(1, policy.max_retries + 2):
        try:
            last_result = operation()
            last_result["attempt_count"] = attempt
            last_result.setdefault("crawl_info", {})["attempt_count"] = attempt
            if last_result.get("success"):
                return last_result, ""
            last_error = str(last_result.get("error") or "crawl_failed")
        except Exception as exc:  # pragma: no cover - optional runtime/network
            last_error = f"{type(exc).__name__}: {exc}"
        if attempt <= policy.max_retries and policy.retry_delay_seconds:
            time.sleep(policy.retry_delay_seconds * attempt)
    if last_result:
        last_result["failure_reason"] = last_result.get("failure_reason") or "retries_exhausted"
    return last_result, last_error


def _record_strategy(result: dict[str, Any], strategy: str, policy: VulnerabilityCrawlPolicy) -> dict[str, Any]:
    result["crawl_strategy"] = strategy
    result["effective_timeout_seconds"] = policy.timeout_seconds
    result.setdefault("crawl_info", {})["strategy"] = strategy
    result["crawl_info"]["effective_timeout_seconds"] = policy.timeout_seconds
    return result


def _crawl4ai_sync(candidate: dict[str, Any], *, policy: VulnerabilityCrawlPolicy) -> dict[str, Any]:  # pragma: no cover - optional dependency
    from crawl4ai import AsyncWebCrawler, BrowserConfig, CrawlerRunConfig

    async def run() -> dict[str, Any]:
        browser_config = _construct_supported(
            BrowserConfig,
            headless=True,
            user_agent=policy.user_agent,
            verbose=False,
            enable_stealth=True,
        )
        run_config = _construct_supported(
            CrawlerRunConfig,
            page_timeout=int(policy.timeout_seconds * 1000),
            delay_before_return_html=policy.js_wait_seconds,
            wait_for=policy.wait_for_selector or None,
            remove_consent_popups=True,
            simulate_user=True,
            magic=True,
        )
        async with AsyncWebCrawler(config=browser_config) as crawler:
            result = await crawler.arun(url=str(candidate.get("url")), config=run_config)
            if not getattr(result, "success", False):
                error = str(getattr(result, "error_message", "crawl4ai_failed"))
                return _failed(candidate, error, failure_reason="crawl4ai_failed")
            markdown = _markdown_text(getattr(result, "markdown", ""))
            metadata = dict(getattr(result, "metadata", {}) or {})
            metadata.update(
                {
                    "status_code": getattr(result, "status_code", None),
                    "links": getattr(result, "links", {}) or {},
                    "media": getattr(result, "media", {}) or {},
                }
            )
            return _success(candidate, markdown=markdown, mode="crawl4ai", metadata=metadata)

    return asyncio.run(run())


def _construct_supported(factory: Any, **kwargs: Any) -> Any:
    signature = inspect.signature(factory)
    supported = {key: value for key, value in kwargs.items() if key in signature.parameters and value is not None}
    return factory(**supported)


def _markdown_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    for attribute in ("fit_markdown", "raw_markdown", "markdown_with_citations"):
        text = getattr(value, attribute, "")
        if text:
            return str(text)
    return str(value or "")


def _urllib_crawl(candidate: dict[str, Any], *, policy: VulnerabilityCrawlPolicy) -> dict[str, Any]:
    url = str(candidate.get("url") or "")
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": policy.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/pdf;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.8",
        },
    )
    started = time.time()
    try:
        with urllib.request.urlopen(request, timeout=policy.timeout_seconds) as response:  # noqa: S310 - validated public discovery URL
            raw = response.read(policy.max_response_bytes)
            content_type = response.headers.get("content-type", "")
            status_code = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        return _failed(candidate, f"HTTP {exc.code}", failure_reason="http_error")
    except urllib.error.URLError as exc:
        return _failed(candidate, str(exc.reason), failure_reason="network_error")
    html = raw.decode("utf-8", errors="replace")
    title = _title(html) or candidate.get("title") or url
    text = _html_to_text(html)
    return _success(
        candidate,
        markdown=text,
        title=title,
        mode="urllib",
        metadata={"content_type": content_type, "status_code": status_code, "elapsed_ms": int((time.time() - started) * 1000)},
    )


def _bounded_int(value: Any, default: int, *, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(1, min(parsed, maximum))


def _success(
    candidate: dict[str, Any],
    *,
    markdown: str,
    mode: str,
    title: str | None = None,
    metadata: dict[str, Any] | None = None,
    attempt_count: int = 1,
) -> dict[str, Any]:
    metadata = metadata or {}
    links = metadata.pop("links", {})
    media = metadata.pop("media", {})
    return {
        **candidate,
        "title": title or candidate.get("title") or candidate.get("url") or "未命名抓取页",
        "success": True,
        "error": "",
        "failure_reason": "",
        "markdown": markdown,
        "cleaned_text": markdown,
        "markdown_length": len(markdown),
        "content_length": len(markdown),
        "crawl_mode": mode,
        "attempt_count": attempt_count,
        "metadata": metadata,
        "links": links,
        "images": media.get("images", []) if isinstance(media, dict) else [],
        "crawl_info": {"success": True, "mode": mode, "attempt_count": attempt_count, **metadata},
    }


def _failed(
    candidate: dict[str, Any],
    error: str,
    *,
    failure_reason: str = "crawl_failed",
    attempt_count: int = 1,
) -> dict[str, Any]:
    return {
        **candidate,
        "success": False,
        "error": error,
        "failure_reason": failure_reason,
        "markdown": "",
        "cleaned_text": "",
        "markdown_length": 0,
        "content_length": 0,
        "crawl_mode": "failed",
        "attempt_count": attempt_count,
        "metadata": {},
        "links": {},
        "images": [],
        "crawl_info": {"success": False, "error": error, "failure_reason": failure_reason, "attempt_count": attempt_count},
    }


def _title(html: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return unescape(re.sub(r"\s+", " ", match.group(1)).strip()) if match else ""


def _html_to_text(html: str) -> str:
    html = re.sub(r"<script[\s\S]*?</script>", " ", html, flags=re.IGNORECASE)
    html = re.sub(r"<style[\s\S]*?</style>", " ", html, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html)
    text = unescape(text)
    return re.sub(r"[ \t\r\f\v]+", " ", re.sub(r"\n\s*\n+", "\n\n", text)).strip()
