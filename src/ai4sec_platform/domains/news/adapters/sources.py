from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
import time
from typing import Any

import yaml

from ai4sec_platform.core.config import Settings
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.registry import SourceRegistry


def collect_news_sources(settings: Settings, params: dict[str, Any]) -> list[dict[str, Any]]:
    mode = str(params.get("mode") or "shadow")
    if mode != "shadow":
        raise ValueError(f"Unsupported news source mode: {mode}")
    config = _load_config(settings.project_root)
    collection_config = config.get("collection", {})
    params = {
        **{key: collection_config[key] for key in ["retry_attempts", "retry_base_delay_seconds", "retry_jitter_seconds", "retry_max_delay_seconds"] if key in collection_config},
        **params,
    }
    source_names = ["arxiv", "github", "rss", "x", "asis", "awesome"]
    requested = set(params["sources"]) if "sources" in params else set(source_names)
    source_configs = config.get("sources", {})
    enabled_sources = [source for source in source_names if source in requested and source_configs.get(source, {}).get("enabled", True)]
    disabled_records = {
        source: _disabled_source_record(source, source_configs.get(source, {}), mode)
        for source in source_names
        if source in requested and not source_configs.get(source, {}).get("enabled", True)
    }
    max_workers = max(1, min(len(enabled_sources), int(params.get("source_workers") or config.get("collection", {}).get("max_workers", 4))))
    records_by_source: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="news-source") as pool:
        futures = {pool.submit(_collect_live_source, settings, source, config.get("sources", {}).get(source, {}), params, mode): source for source in enabled_sources}
        for future in as_completed(futures):
            source = futures[future]
            try:
                records_by_source[source] = future.result()
            except Exception as exc:
                records_by_source[source] = {"source": source, "path": f"connector:{source}", "exists": True, "mode": mode, "items": [], "errors": [str(exc)], "metadata": {"worker_failure": True}}
    return [records_by_source.get(source) or disabled_records[source] for source in source_names if source in enabled_sources or source in disabled_records]


def _disabled_source_record(source: str, source_config: dict[str, Any], mode: str) -> dict[str, Any]:
    reason = str(source_config.get("disabled_reason") or f"{source} source is disabled")
    return {
        "source": source,
        "path": f"connector:{source}",
        "exists": True,
        "mode": mode,
        "status": "disabled",
        "health": "disabled",
        "items": [],
        "errors": [],
        "metadata": {"disabled": True, "disabled_reason": reason},
    }


def _collect_live_source(settings: Settings, source: str, source_config: dict[str, Any], params: dict[str, Any], mode: str) -> dict[str, Any]:
    connector = SourceRegistry().get(source)
    runtime_params = {
        key: params[key]
        for key in ["timeout_seconds", "retry_attempts", "retry_base_delay_seconds", "retry_jitter_seconds", "retry_max_delay_seconds"]
        if key in params
    }
    runtime_params.setdefault("timeout_seconds", 30)
    if source in {"arxiv", "github"}:
        items: list[dict[str, Any]] = []
        errors: list[str] = []
        metadata: list[dict[str, Any]] = []
        requests = _arxiv_requests(source_config, params) if source == "arxiv" else _github_requests(source_config, params)
        for index, request_params in enumerate(requests):
            delay = float(request_params.pop("_delay_seconds", params.get("source_request_delay_seconds", source_config.get("request_delay_seconds", 0))))
            result = connector.fetch(SourceFetchRequest(source_name=source, config=source_config, params={**request_params, **runtime_params}))
            items.extend(result.items)
            errors.extend(result.errors)
            metadata.append(result.metadata)
            if delay > 0 and index < len(requests) - 1:
                time.sleep(delay)
        items = _dedupe_collected_items(source, items)
        return {
            "source": source,
            "path": f"connector:{source}",
            "exists": True,
            "mode": mode,
            "items": items,
            "errors": errors,
            "metadata": {"request_count": len(requests), "requests": metadata},
        }
    source_params: dict[str, Any] = {
        **runtime_params,
        "incremental_state": (params.get("_incremental_states") or {}).get(source, {}),
    }
    result = connector.fetch(SourceFetchRequest(source_name=source, config=source_config, params=source_params))
    return {"source": source, "path": f"connector:{source}", "exists": True, "mode": mode, "items": result.items, "errors": result.errors, "metadata": result.metadata}


def _load_config(project_root: Path) -> dict[str, Any]:
    path = project_root / "configs" / "news.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def load_news_source_configs(project_root: Path) -> dict[str, dict[str, Any]]:
    return _load_config(project_root).get("sources", {})


def _arxiv_requests(config: dict[str, Any], params: dict[str, Any]) -> list[dict[str, Any]]:
    requests = [{"category": category, "_delay_seconds": config.get("category_delay_seconds", 1)} for category in config.get("categories") or []]
    backfill_days = int(params.get("arxiv_backfill_days") or config.get("category_backfill_days", 2))
    backfill_cutoff = (datetime.now(timezone.utc) - timedelta(days=backfill_days)).date().isoformat()
    backfill_max_results = min(int(config.get("max_results_per_category", 100)) * max(backfill_days, 1), 500)
    requests.extend({"query": f"cat:{category}", "category_backfill": category, "max_results": backfill_max_results, "published_after": backfill_cutoff, "_delay_seconds": config.get("keyword_delay_seconds", 3)} for category in config.get("categories") or [])
    keyword_max_results = int(params.get("max_results") or config.get("keyword_max_results", 50))
    keyword_cutoff = (datetime.now(timezone.utc) - timedelta(days=int(config.get("keyword_lookback_days", 30)))).date().isoformat()
    for keyword in config.get("keyword_queries") or []:
        terms = [term for term in str(keyword).split() if term]
        if terms:
            requests.append({"query": " AND ".join(f"all:{term}" for term in terms), "max_results": keyword_max_results, "keyword": keyword, "published_after": keyword_cutoff, "_delay_seconds": config.get("keyword_delay_seconds", 3)})
    return requests


def _dedupe_collected_items(source: str, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in items:
        key = str(item.get("id") or item.get("full_name") or item.get("html_url") or item.get("url") or "")
        normalized_key = key.lower() if source == "github" else key
        if normalized_key and normalized_key in seen:
            continue
        if normalized_key:
            seen.add(normalized_key)
        output.append(item)
    return output


def _github_requests(config: dict[str, Any], params: dict[str, Any]) -> list[dict[str, Any]]:
    lookback_days = int(params.get("lookback_days") or config.get("lookback_days", 7))
    cutoff = (datetime.now(timezone.utc) - timedelta(days=lookback_days)).date().isoformat()
    max_pages = int(params.get("max_pages") or config.get("max_pages_per_query", 5))
    per_page = int(params.get("max_results") or config.get("per_page", 100))
    requests: list[dict[str, Any]] = []
    base_queries = [f"topic:{topic}" for topic in config.get("topics") or []] + [str(query) for query in config.get("keyword_queries") or []]
    creation_queries = [str(query) for query in config.get("creation_queries") or []]
    high_star_queries = [str(query) for query in config.get("high_star_queries") or []]
    if params.get("collection_profile") == "daily":
        rotation_key = str(params.get("date") or datetime.now(timezone.utc).date().isoformat())
        base_queries = _rotated_queries(base_queries, int(config.get("daily_base_query_limit") or 18), rotation_key)
        creation_queries = _rotated_queries(creation_queries, int(config.get("daily_creation_query_limit") or 3), rotation_key)
        high_star_queries = _rotated_queries(high_star_queries, int(config.get("daily_high_star_query_limit") or 2), rotation_key)
    for query in base_queries:
        requests.append({"query": f"{query} created:>{cutoff}", "channel": "new", "max_pages": max_pages, "max_results": per_page})
        requests.append({"query": f"{query} pushed:>{cutoff} stars:>={int(config.get('min_stars', 3))}", "channel": "updated", "max_pages": max_pages, "max_results": per_page})
    for query in creation_queries:
        requests.append({"query": f"{query} created:>{cutoff} stars:>=0", "channel": "new", "max_pages": 1, "max_results": per_page})
    for query in high_star_queries:
        requests.append({"query": f"{query} pushed:>{cutoff}", "channel": "high_star", "max_pages": 2, "max_results": per_page})
    return requests


def _rotated_queries(queries: list[str], limit: int, rotation_key: str) -> list[str]:
    if not queries or limit <= 0 or limit >= len(queries):
        return queries
    try:
        day_number = datetime.fromisoformat(rotation_key).date().toordinal()
    except ValueError:
        day_number = sum(ord(character) for character in rotation_key)
    offset = (day_number * limit) % len(queries)
    rotated = queries[offset:] + queries[:offset]
    return rotated[:limit]
