from __future__ import annotations

import urllib.parse
import xml.etree.ElementTree as ET

from ai4sec_platform.schemas.sources import SourceFetchRequest, SourceHealth
from ai4sec_platform.sources.connectors.news.base_live import NewsLiveConnector
from ai4sec_platform.sources.result import SourceFetchResult


class ArxivConnector(NewsLiveConnector):
    connector_name = "arxiv"
    source_type = "paper"
    api_url = "https://export.arxiv.org/api/query"

    def health_check(self, config: dict) -> SourceHealth:
        return SourceHealth(status="ok", message=self.api_url)

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        category = str(request.params.get("category") or "")
        if category:
            url = f"https://rss.arxiv.org/rss/{category}"
            try:
                raw = self.get_bytes(url, timeout=int(request.params.get("timeout_seconds") or 30))
                return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=_parse_rss_feed(raw, category), raw_text=raw.decode("utf-8", errors="replace"), metadata={"url": url, "category": category, "channel": "category_rss"})
            except Exception as exc:
                return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"url": url, "category": category, "channel": "category_rss"}, errors=[str(exc)])
        query = str(request.params.get("query") or request.config.get("query") or 'all:"AI security"')
        max_results = min(500, int(request.params.get("max_results") or request.config.get("max_results") or 30))
        url = f"{self.api_url}?{urllib.parse.urlencode({'search_query': query, 'start': 0, 'max_results': max_results, 'sortBy': 'submittedDate', 'sortOrder': 'descending'})}"
        try:
            raw = self.get_bytes(url, timeout=int(request.params.get("timeout_seconds") or 30))
            items = _parse_feed(raw)
            published_after = str(request.params.get("published_after") or "")
            if published_after:
                items = [item for item in items if str(item.get("published") or "")[:10] >= published_after]
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, items=items, raw_text=raw.decode("utf-8", errors="replace"), metadata={"url": url, "query": query, "channel": "category_backfill" if request.params.get("category_backfill") else "keyword"})
        except Exception as exc:
            return SourceFetchResult(source_name=request.source_name, connector_name=self.connector_name, metadata={"url": url, "query": query}, errors=[str(exc)])


def _parse_feed(raw: bytes) -> list[dict]:
    root = ET.fromstring(raw)
    namespace = {"atom": "http://www.w3.org/2005/Atom"}
    items = []
    for entry in root.findall("atom:entry", namespace):
        links = {link.attrib.get("rel", "alternate"): link.attrib.get("href", "") for link in entry.findall("atom:link", namespace)}
        categories = [node.attrib.get("term", "") for node in entry.findall("atom:category", namespace)]
        items.append({
            "id": _text(entry, "atom:id", namespace),
            "title": _text(entry, "atom:title", namespace),
            "summary": _text(entry, "atom:summary", namespace),
            "published": _text(entry, "atom:published", namespace),
            "updated": _text(entry, "atom:updated", namespace),
            "url": links.get("alternate") or _text(entry, "atom:id", namespace),
            "authors": [_text(author, "atom:name", namespace) for author in entry.findall("atom:author", namespace)],
            "categories": [category for category in categories if category],
        })
    return items


def _parse_rss_feed(raw: bytes, category: str) -> list[dict]:
    root = ET.fromstring(raw)
    items: list[dict] = []
    namespace = {
        "dc": "http://purl.org/dc/elements/1.1/",
        "arxiv": "http://arxiv.org/schemas/atom",
    }
    for entry in root.findall("./channel/item"):
        link = _plain_text(entry, "link")
        raw_id = _plain_text(entry, "guid") or link
        authors = [_node_text(author) for author in entry.findall("dc:creator", namespace)]
        categories = [_node_text(node) for node in entry.findall("category")]
        items.append({
            "id": raw_id,
            "title": _plain_text(entry, "title"),
            "summary": _plain_text(entry, "description"),
            "published": _plain_text(entry, "pubDate"),
            "updated": "",
            "url": link or raw_id,
            "authors": [author for author in authors if author],
            "categories": [value for value in categories if value] or [category],
            "primary_category": category,
            "announce_type": _find_optional_text(entry, "arxiv:announce_type", namespace),
        })
    return items


def _text(node: ET.Element, path: str, namespace: dict[str, str]) -> str:
    child = node.find(path, namespace)
    return " ".join((child.text or "").split()) if child is not None else ""


def _plain_text(node: ET.Element, path: str) -> str:
    return _node_text(node.find(path))


def _find_optional_text(node: ET.Element, path: str, namespace: dict[str, str]) -> str:
    return _node_text(node.find(path, namespace))


def _node_text(node: ET.Element | None) -> str:
    return " ".join("".join(node.itertext()).split()) if node is not None else ""
