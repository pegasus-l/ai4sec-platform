from __future__ import annotations

import http.cookiejar
import json
import os
import urllib.parse
import urllib.request

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.news.base_live import NewsLiveConnector, retry_call
from ai4sec_platform.sources.result import SourceFetchResult


class AsisConnector(NewsLiveConnector):
    connector_name = "asis"
    source_type = "discovery"

    def health_check(self, config: dict) -> SourceHealth:
        configured = bool(config.get("base_url") and os.getenv("ASIS_USERNAME") and os.getenv("ASIS_PASSWORD"))
        return SourceHealth(status="ok" if configured else "missing", message="ASIS_BASE_URL/ASIS_USERNAME/ASIS_PASSWORD")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        base_url = str(request.config.get("base_url") or os.getenv("ASIS_BASE_URL") or "").rstrip("/")
        username = os.getenv("ASIS_USERNAME", "")
        password = os.getenv("ASIS_PASSWORD", "")
        timeout = int(request.params.get("timeout_seconds") or 30)
        if not base_url or not username or not password:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["ASIS credentials are not configured"])
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        try:
            login = urllib.request.Request(f"{base_url}/api/auth/login", data=urllib.parse.urlencode({"username": username, "password": password, "next": "/"}).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
            retry_call(lambda: opener.open(login, timeout=timeout).read())
            limit = min(500, int(request.config.get("fetch_limit") or 500))
            items_request = urllib.request.Request(f"{base_url}/api/items?limit={limit}&offset=0", headers={"Accept": "application/json"})
            raw_text = retry_call(lambda: opener.open(items_request, timeout=min(timeout, 60)).read().decode("utf-8"))
            raw = json.loads(raw_text)
            raw_items = raw if isinstance(raw, list) else raw.get("items") or []
            min_score = int(request.config.get("min_score") or 0)
            incremental_state = request.params.get("incremental_state") or {}
            state_ids = [str(value) for value in incremental_state.get("scanned_ids") or []]
            scanned_ids = set(state_ids)
            state_max_ids = max(100, int(request.config.get("state_max_ids") or 20_000))
            items = []
            for item in raw_items:
                if not isinstance(item, dict):
                    continue
                item_id = item.get("id")
                if item_id is None or str(item_id).strip() == "":
                    continue
                state_id = f"asis:{item_id}"
                if state_id not in scanned_ids and int(item.get("score_total") or 0) >= min_score:
                    items.append(_normalize_item(item))
                if state_id not in scanned_ids:
                    scanned_ids.add(state_id)
                    state_ids.append(state_id)
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, raw_text=raw_text, metadata={"base_url": base_url, "limit": limit, "total_fetched": len(raw_items), "min_score": min_score, "next_incremental_state": {"scanned_ids": state_ids[-state_max_ids:]}})
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"base_url": base_url}, errors=[str(exc)])


def _normalize_item(item: dict) -> dict:
    return {
        "id": f"asis:{item.get('id')}",
        "asis_id": item.get("id"),
        "title": item.get("title") or "",
        "title_zh": item.get("title_zh") or "",
        "url": item.get("canonical_url") or "",
        "paper_url": item.get("paper_url") or "",
        "summary": item.get("summary") or "",
        "published": str(item.get("published_at") or "")[:10],
        "item_type": item.get("item_type") or "",
        "primary_category": item.get("primary_category") or "",
        "sub_category": item.get("sub_category") or "",
        "score_total": int(item.get("score_total") or 0),
        "recommendation_reason": item.get("recommendation_reason") or "",
        "author": item.get("author") or "",
        "source": "asis",
    }
