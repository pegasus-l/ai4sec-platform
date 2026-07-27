from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any

from ai4sec_platform.core.env import load_env_file
from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.result import SourceFetchResult

DEFAULT_BASE_URL = "https://api.anysearch.com"


class AnysearchConnector:
    connector_name = "anysearch"
    source_type = "anysearch"

    def health_check(self, config: dict) -> SourceHealth:
        load_env_file()
        api_key = config.get("api_key") or os.getenv("ANYSEARCH_API_KEY", "")
        if api_key:
            return SourceHealth(status="configured", message="ANYSEARCH_API_KEY is set")
        return SourceHealth(status="degraded", message="ANYSEARCH_API_KEY is not set; seed_candidates/offline mode only")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        load_env_file()
        params = request.params or {}
        seed_candidates = params.get("seed_candidates") or params.get("items")
        if isinstance(seed_candidates, list):
            return SourceFetchResult(
                source_name=request.source_name,
                connector_name=self.connector_name,
                items=[_normalize_candidate(item, query=item.get("search_keyword") or item.get("query") or "", rank=index + 1) for index, item in enumerate(seed_candidates) if isinstance(item, dict)],
                metadata={"mode": "seed_candidates", "count": len(seed_candidates)},
            )

        queries = _queries(params)
        if not queries:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["missing_query"])

        api_key = params.get("api_key") or request.config.get("api_key") or os.getenv("ANYSEARCH_API_KEY", "")
        if not api_key:
            return SourceFetchResult(
                source_name=request.source_name,
                connector_name=self.connector_name,
                metadata={"queries": queries, "mode": "not_configured"},
                errors=["missing_anysearch_api_key"],
            )

        base_url = str(params.get("base_url") or request.config.get("base_url") or os.getenv("ANYSEARCH_BASE_URL", DEFAULT_BASE_URL)).rstrip("/")
        timeout = float(params.get("timeout") or request.config.get("timeout") or 30)
        max_results = int(params.get("max_results") or request.config.get("max_results") or 10)
        domain = params.get("domain") or request.config.get("domain")
        zone = params.get("zone") or request.config.get("zone")
        language = params.get("language") or request.config.get("language")
        max_attempts = max(1, min(int(params.get("search_max_attempts") or 4), 10))
        retry_delay = max(0.0, float(params.get("search_retry_delay") or 1.0))

        items: list[dict[str, Any]] = []
        errors: list[str] = []
        raw_responses: list[dict[str, Any]] = []
        for query in queries:
            payload: dict[str, Any] = {"query": query, "max_results": max_results}
            if domain:
                payload["domain"] = domain
            if zone:
                payload["zone"] = zone
            if language:
                payload["language"] = language
            for attempt in range(1, max_attempts + 1):
                try:
                    raw = _post_json(f"{base_url}/v1/search", payload, api_key=api_key, timeout=timeout)
                    raw_responses.append({"query": query, "raw": raw, "attempt": attempt})
                    results = raw.get("results", []) if isinstance(raw, dict) else []
                    for rank, item in enumerate(results, start=1):
                        if isinstance(item, dict):
                            items.append(_normalize_candidate(item, query=query, rank=rank))
                    break
                except Exception as exc:  # pragma: no cover - depends on external service
                    if attempt == max_attempts:
                        errors.append(f"{query}: {exc}")
                    elif retry_delay:
                        time.sleep(retry_delay)

        return SourceFetchResult(
            source_name=request.source_name,
            connector_name=self.connector_name,
            items=items,
            metadata={"queries": queries, "max_results": max_results, "max_attempts": max_attempts, "raw_response_count": len(raw_responses)},
            errors=errors,
        )


def _queries(params: dict[str, Any]) -> list[str]:
    value = params.get("queries") or params.get("query") or params.get("keywords")
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return []


def _post_json(url: str, payload: dict[str, Any], *, api_key: str, timeout: float) -> dict[str, Any]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - configured user endpoint
            parsed = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:  # pragma: no cover - external service
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc
    if isinstance(parsed, dict) and parsed.get("code") not in (None, 0):
        raise RuntimeError(parsed.get("message") or f"AnySearch code={parsed.get('code')}")
    data = parsed.get("data", parsed) if isinstance(parsed, dict) else {}
    return data if isinstance(data, dict) else {"results": []}


def _normalize_candidate(item: dict[str, Any], *, query: str, rank: int) -> dict[str, Any]:
    url = str(item.get("url") or item.get("link") or item.get("href") or "")
    return {
        "candidate_id": item.get("id") or f"anysearch:{rank}:{url}",
        "title": item.get("title") or url or "未命名搜索结果",
        "url": url,
        "snippet": item.get("snippet") or item.get("content") or item.get("summary") or "",
        "content": item.get("content") or item.get("markdown") or item.get("cleaned_text") or item.get("snippet") or "",
        "markdown": item.get("markdown") or "",
        "cleaned_text": item.get("cleaned_text") or "",
        "score": item.get("score", 1.0),
        "rank": rank,
        "search_keyword": query,
        "source_engine": "anysearch",
        "raw": item,
    }
