from __future__ import annotations

from datetime import datetime, timezone
import re
import time
from typing import Any

from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.news.adapters.sources import load_news_source_configs
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.registry import SourceRegistry


NEWS_SOURCES = ("arxiv", "github", "rss", "x", "asis", "awesome")


def probe_news_sources(conn, settings: Settings, sources: list[str] | None = None, *, timeout_seconds: int = 10) -> list[dict[str, Any]]:
    configured = load_news_source_configs(settings.project_root)
    requested = set(sources or NEWS_SOURCES)
    results = []
    for source in NEWS_SOURCES:
        if source not in requested:
            continue
        result = _probe_source(source, configured.get(source, {}), timeout_seconds)
        repo.create_data_source(
            conn,
            domain="news",
            name=source,
            source_type="health_probe",
            status=result["status"],
            latest_at=result["checked_at"],
            health=result["health"],
            summary=result,
        )
        results.append(result)
    conn.commit()
    return results


def _probe_source(source: str, config: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    checked_at = datetime.now(timezone.utc).isoformat()
    if not config.get("enabled", True):
        return _result(source, "disabled", "disabled", str(config.get("disabled_reason") or "source is disabled"), checked_at, 0)
    connector = SourceRegistry().get(source)
    configured_health = connector.health_check(config)
    if configured_health.status in {"missing", "disabled"}:
        return _result(source, configured_health.status, configured_health.status, configured_health.message, checked_at, 0)
    started = time.monotonic()
    try:
        fetch_result = connector.fetch(SourceFetchRequest(source_name=source, config=_probe_config(source, config), params=_probe_params(source, timeout_seconds)))
        if fetch_result.errors:
            error = str(fetch_result.errors[0])
            status = classify_health_error(error)
            return _result(source, status, status, error, checked_at, _elapsed_ms(started), errors=fetch_result.errors)
        return _result(source, "healthy", "healthy", f"probe succeeded; {len(fetch_result.items)} item(s)", checked_at, _elapsed_ms(started), items=len(fetch_result.items), metadata=fetch_result.metadata)
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        status = classify_health_error(error)
        return _result(source, status, status, error, checked_at, _elapsed_ms(started), errors=[error])


def classify_health_error(error: str) -> str:
    normalized = error.lower()
    status_code = re.search(r"\b(401|402|403|408|429|5\d\d)\b", normalized)
    if "401" in normalized or "403" in normalized or "unauthorized" in normalized or "forbidden" in normalized:
        return "auth_failed"
    if "402" in normalized or "quota" in normalized or "payment required" in normalized:
        return "quota_exhausted"
    if "429" in normalized or "rate limit" in normalized:
        return "rate_limited"
    if status_code and status_code.group(1).startswith("5"):
        return "upstream_failed"
    if "timeout" in normalized or "timed out" in normalized:
        return "timeout"
    return "unhealthy"


def _probe_config(source: str, config: dict[str, Any]) -> dict[str, Any]:
    result = dict(config)
    if source == "github":
        result["readme_limit"] = 0
    if source == "awesome":
        result["repositories"] = list(config.get("repositories") or [])[:1]
    if source == "rss":
        result["feeds"] = list(config.get("feeds") or [])[:1]
        for feed in result["feeds"]:
            if isinstance(feed, dict):
                feed["paginate"] = False
    if source == "asis":
        result["fetch_limit"] = 1
    return result


def _probe_params(source: str, timeout_seconds: int) -> dict[str, Any]:
    if source == "arxiv":
        return {"query": "id:2501.00001", "max_results": 1, "timeout_seconds": timeout_seconds}
    if source == "github":
        return {"query": "AI security", "max_results": 1, "max_pages": 1, "timeout_seconds": timeout_seconds}
    return {"timeout_seconds": timeout_seconds}


def _result(source: str, status: str, health: str, message: str, checked_at: str, latency_ms: int, **extra: Any) -> dict[str, Any]:
    return {"source": source, "status": status, "health": health, "message": message, "checked_at": checked_at, "latency_ms": latency_ms, **extra}


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
