from __future__ import annotations

import json
import os
import time
import urllib.parse

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.news.base_live import NewsLiveConnector
from ai4sec_platform.sources.result import SourceFetchResult


class XFeedConnector(NewsLiveConnector):
    connector_name = "x"
    source_type = "discovery"

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok" if os.getenv("GETXAPI_KEY") else "missing", message="GETXAPI_KEY")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        if self.has_local_path(request):
            return super().fetch(request)
        api_key = os.getenv("GETXAPI_KEY", "")
        accounts = request.config.get("accounts") or []
        if not api_key:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, errors=["GETXAPI_KEY is not configured"])
        api_base = str(request.config.get("api_base") or "https://api.getxapi.com").rstrip("/")
        count = min(100, int(request.config.get("tweets_per_account") or 20))
        min_likes = int(request.config.get("min_likes") or 0)
        skip_pure_replies = bool(request.config.get("skip_pure_replies", True))
        timeout = int(request.params.get("timeout_seconds") or 30)
        items: list[dict] = []
        errors: list[str] = []
        for account in accounts:
            username = str(account.get("username") if isinstance(account, dict) else account)
            url = f"{api_base}/twitter/tweet/advanced_search?{urllib.parse.urlencode({'q': f'from:{username}', 'count': count})}"
            try:
                raw = self._fetch_json(url, api_key, timeout=timeout)
                tweets = raw.get("tweets") or raw.get("data") or []
                for tweet in tweets:
                    if not isinstance(tweet, dict):
                        continue
                    likes = int(tweet.get("likeCount") or 0)
                    bookmarks = int(tweet.get("bookmarkCount") or 0)
                    if skip_pure_replies and tweet.get("isReply") and likes < min_likes and bookmarks < 3:
                        continue
                    author = tweet.get("author") if isinstance(tweet.get("author"), dict) else {}
                    entities = tweet.get("entities") if isinstance(tweet.get("entities"), dict) else {}
                    urls = [value.get("expanded_url") or value.get("url") for value in entities.get("urls") or [] if isinstance(value, dict)]
                    items.append({"id": f"x:{tweet.get('id')}", "title": str(tweet.get("text") or "")[:120], "text": tweet.get("text", ""), "url": tweet.get("url", ""), "reference_urls": [value for value in urls if value], "author": author.get("userName", username), "published": tweet.get("createdAt", ""), "likes": likes, "bookmarks": bookmarks, "retweets": int(tweet.get("retweetCount") or 0), "source": "x"})
            except Exception as exc:
                errors.append(f"{username}: {exc}")
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, metadata={"accounts": len(accounts)}, errors=errors)

    def _fetch_json(self, url: str, api_key: str, *, timeout: int) -> dict:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                return json.loads(self.get_bytes(url, timeout=timeout, headers={"Authorization": f"Bearer {api_key}"}).decode("utf-8"))
            except Exception as exc:
                last_error = exc
                if attempt < 2:
                    time.sleep(2 * (attempt + 1))
        raise RuntimeError(str(last_error))
