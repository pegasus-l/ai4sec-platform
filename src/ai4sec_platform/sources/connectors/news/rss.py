from __future__ import annotations

import json
import xml.etree.ElementTree as ET
import urllib.parse

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.news.base_live import NewsLiveConnector
from ai4sec_platform.sources.result import SourceFetchResult


class RssConnector(NewsLiveConnector):
    connector_name = "rss"
    source_type = "article"

    def health_check(self, config: dict) -> SourceHealth:
        feeds = config.get("feeds") or []
        return SourceHealth(status="ok" if feeds else "missing", message=f"{len(feeds)} feeds")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        if self.has_local_path(request):
            return super().fetch(request)
        feeds = request.config.get("feeds") or []
        items: list[dict] = []
        errors: list[str] = []
        feed_metrics: list[dict] = []
        timeout = int(request.params.get("timeout_seconds") or 30)
        for feed in feeds:
            feed_config = feed if isinstance(feed, dict) else {"name": str(feed), "url": str(feed)}
            url = str(feed_config.get("url") or "")
            if not url:
                continue
            pages = 0
            feed_items: list[dict] = []
            seen_page_keys: set[tuple[str, ...]] = set()
            max_pages = int(feed_config.get("max_pages") or 1)
            page_size = int(feed_config.get("page_size") or 30)
            for page in range(max_pages if feed_config.get("paginate") else 1):
                page_url = _page_url(url, page * page_size) if feed_config.get("paginate") else url
                try:
                    raw = self.get_bytes(page_url, timeout=timeout)
                    page_items = _parse_feed(raw, page_url, feed_config)
                except Exception as exc:
                    errors.append(f"{page_url}: {exc}")
                    break
                pages += 1
                page_key = tuple(str(item.get("link") or item.get("guid") or "") for item in page_items)
                if page_key in seen_page_keys:
                    break
                seen_page_keys.add(page_key)
                for item in page_items:
                    if not item.get("text") and item.get("feed_item_id") and feed_config.get("article_api_base"):
                        item["text"] = self._fetch_article_text(str(feed_config["article_api_base"]), str(item["feed_item_id"]), timeout=min(timeout, 15))
                feed_items.extend(page_items)
                if len(page_items) < page_size:
                    break
            items.extend(feed_items)
            feed_metrics.append({"name": feed_config.get("name") or url, "url": url, "pages": pages, "items": len(feed_items)})
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, metadata={"feeds": feed_metrics}, errors=errors)

    def _fetch_article_text(self, api_base: str, feed_item_id: str, *, timeout: int) -> str:
        try:
            raw = json.loads(self.get_bytes(f"{api_base.rstrip('/')}/{urllib.parse.quote(feed_item_id)}", timeout=timeout).decode("utf-8"))
            article = raw.get("data") if isinstance(raw.get("data"), dict) else {}
            return "\n".join(value for value in [str(article.get("description") or ""), str(article.get("content") or "")] if value)
        except Exception:
            return ""


def _parse_feed(raw: bytes, feed_url: str, feed_config: dict) -> list[dict]:
    root = ET.fromstring(raw)
    items: list[dict] = []
    channel_items = root.findall("./channel/item")
    if channel_items:
        for item in channel_items:
            description = _child_text(item, "description")
            content = _find_namespaced_text(item, "encoded")
            items.append({
                "title": _child_text(item, "title"),
                "link": _child_text(item, "link"),
                "guid": _child_text(item, "guid"),
                "summary": description,
                "text": content,
                "published": _child_text(item, "pubDate"),
                "author": _child_text(item, "author"),
                "categories": [_node_text(node) for node in item.findall("category")],
                "feed_item_id": _child_text(item, "id"),
                "feed_url": feed_url,
                "feed_name": feed_config.get("name") or "",
                "feed_source_type": feed_config.get("source_type") or "rss",
            })
        return items
    namespace = {"atom": "http://www.w3.org/2005/Atom"}
    for entry in root.findall("atom:entry", namespace):
        link = entry.find("atom:link", namespace)
        items.append({
            "title": _find_text(entry, "atom:title", namespace),
            "link": link.attrib.get("href", "") if link is not None else "",
            "summary": _find_text(entry, "atom:summary", namespace) or _find_text(entry, "atom:content", namespace),
            "published": _find_text(entry, "atom:published", namespace) or _find_text(entry, "atom:updated", namespace),
            "author": _find_text(entry, "atom:author/atom:name", namespace),
            "feed_url": feed_url,
            "feed_name": feed_config.get("name") or "",
            "feed_source_type": feed_config.get("source_type") or "rss",
        })
    return items


def _page_url(url: str, offset: int) -> str:
    parsed = urllib.parse.urlsplit(url)
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    query["offset"] = str(offset)
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment))


def _find_namespaced_text(node: ET.Element, suffix: str) -> str:
    for child in node:
        if child.tag.rsplit("}", 1)[-1] == suffix:
            return _node_text(child)
    return ""


def _child_text(node: ET.Element, tag: str) -> str:
    child = node.find(tag)
    return _node_text(child)


def _find_text(node: ET.Element, path: str, namespace: dict[str, str]) -> str:
    return _node_text(node.find(path, namespace))


def _node_text(node: ET.Element | None) -> str:
    return " ".join("".join(node.itertext()).split()) if node is not None else ""
