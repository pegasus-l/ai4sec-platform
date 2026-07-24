from __future__ import annotations

import http.cookiejar
import json
import os
import urllib.parse
import urllib.request

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.news.base_live import NewsLiveConnector
from ai4sec_platform.sources.result import SourceFetchResult


class AsisConnector(NewsLiveConnector):
    connector_name = "asis"
    source_type = "discovery"

    def health_check(self, config: dict) -> SourceHealth:
        configured = bool(config.get("base_url") and os.getenv("ASIS_USERNAME") and os.getenv("ASIS_PASSWORD"))
        return SourceHealth(status="ok" if configured else "missing", message="ASIS_BASE_URL/ASIS_USERNAME/ASIS_PASSWORD")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        if self.has_local_path(request):
            return super().fetch(request)
        base_url = str(request.config.get("base_url") or os.getenv("ASIS_BASE_URL") or "").rstrip("/")
        username = os.getenv("ASIS_USERNAME", "")
        password = os.getenv("ASIS_PASSWORD", "")
        if not base_url or not username or not password:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["ASIS credentials are not configured"])
        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        try:
            login = urllib.request.Request(f"{base_url}/api/auth/login", data=urllib.parse.urlencode({"username": username, "password": password, "next": "/"}).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
            opener.open(login, timeout=30).read()
            limit = min(500, int(request.config.get("fetch_limit") or 500))
            with opener.open(urllib.request.Request(f"{base_url}/api/items?limit={limit}&offset=0", headers={"Accept": "application/json"}), timeout=60) as response:
                raw_text = response.read().decode("utf-8")
            raw = json.loads(raw_text)
            items = raw if isinstance(raw, list) else raw.get("items") or []
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=[item for item in items if isinstance(item, dict)], raw_text=raw_text, metadata={"base_url": base_url, "limit": limit})
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"base_url": base_url}, errors=[str(exc)])
