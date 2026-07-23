from __future__ import annotations

import xml.etree.ElementTree as ET

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.news.base_live import NewsLiveConnector
from ai4sec_platform.sources.result import SourceFetchResult


class RssConnector(NewsLiveConnector):
    connector_name = "rss"
    source_type = "article"

    def health_check(self, config: dict) -> SourceHealth:
        urls = config.get("urls") or []
        return SourceHealth(status="ok" if urls else "missing", message=f"{len(urls)} feeds")

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        if self.has_local_path(request):
            return super().fetch(request)
        urls = request.params.get("urls") or request.config.get("urls") or []
        if isinstance(urls, str):
            urls = [urls]
        items: list[dict] = []
        errors: list[str] = []
        for url in urls:
            try:
                raw = self.get_bytes(str(url), timeout=int(request.params.get("timeout_seconds") or 30))
                items.extend(_parse_feed(raw, str(url)))
            except Exception as exc:
                errors.append(f"{url}: {exc}")
        return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, metadata={"urls": urls}, errors=errors)


def _parse_feed(raw: bytes, feed_url: str) -> list[dict]:
    root = ET.fromstring(raw)
    items: list[dict] = []
    channel_items = root.findall("./channel/item")
    if channel_items:
        for item in channel_items:
            items.append({
                "title": _child_text(item, "title"),
                "link": _child_text(item, "link"),
                "summary": _child_text(item, "description"),
                "published": _child_text(item, "pubDate"),
                "author": _child_text(item, "author"),
                "categories": [_node_text(node) for node in item.findall("category")],
                "feed_url": feed_url,
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
        })
    return items


def _child_text(node: ET.Element, tag: str) -> str:
    child = node.find(tag)
    return _node_text(child)


def _find_text(node: ET.Element, path: str, namespace: dict[str, str]) -> str:
    return _node_text(node.find(path, namespace))


def _node_text(node: ET.Element | None) -> str:
    return " ".join("".join(node.itertext()).split()) if node is not None else ""
