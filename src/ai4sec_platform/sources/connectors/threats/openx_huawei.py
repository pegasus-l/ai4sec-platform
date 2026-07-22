from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin
from typing import List, Optional, Tuple

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector
from ai4sec_platform.sources.result import SourceFetchResult


class _ApacheIndexParser(HTMLParser):
    """Parse Apache directory listing HTML to extract file entries."""

    def __init__(self):
        super().__init__()
        self.entries: List[Tuple[str, str, str, str, bool]] = []
        self._in_row = False
        self._in_link = False
        self._link_href = ""
        self._link_text = ""
        self._cells: List[str] = []
        self._current_cell_text = ""
        self._in_cell = False
        self._cell_has_link = False
        self._row_has_dir_icon = False
        self._row_is_parent = False

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "tr":
            self._in_row = True
            self._cells = []
            self._row_has_dir_icon = False
            self._row_is_parent = False
            self._link_href = ""
            self._link_text = ""
            self._in_link = False
            self._cell_has_link = False
        elif tag == "td" and self._in_row:
            self._in_cell = True
            self._current_cell_text = ""
            self._cell_has_link = False
        elif tag == "img" and self._in_row:
            alt = attrs_dict.get("alt", "")
            src = attrs_dict.get("src", "")
            if alt == "[DIR]" or "folder" in src:
                self._row_has_dir_icon = True
            if alt == "[PARENTDIR]" or "back" in src:
                self._row_is_parent = True
        elif tag == "a" and self._in_row and self._in_cell:
            self._in_link = True
            self._link_href = attrs_dict.get("href", "")
            self._cell_has_link = True

    def handle_endtag(self, tag):
        if tag == "a" and self._in_link:
            self._in_link = False
        elif tag == "td" and self._in_cell:
            self._in_cell = False
            if self._cell_has_link:
                cell = self._link_text.strip()
            else:
                cell = self._current_cell_text.strip()
            self._cells.append(cell)
        elif tag == "tr" and self._in_row:
            self._in_row = False
            if self._row_is_parent:
                return
            name = self._link_text.strip() if self._link_text.strip() else self._link_href.rstrip("/")
            link_href = self._link_href
            date = ""
            size = ""
            for i, cell in enumerate(self._cells):
                if re.match(r"\d{4}-\d{2}-\d{2}", cell):
                    date = cell
                    if i + 1 < len(self._cells):
                        size = self._cells[i + 1]
                    break
            is_dir = self._row_has_dir_icon
            if name and link_href:
                self.entries.append((name, link_href, date, size, is_dir))

    def handle_data(self, data):
        if self._in_cell:
            if self._in_link:
                self._link_text += data
            else:
                self._current_cell_text += data


def _parse_apache_index(html: str) -> List[Tuple[str, str, str, str, bool]]:
    parser = _ApacheIndexParser()
    parser.feed(html)
    return parser.entries


class OpenXHuaweiConnector(LiveJsonConnector):
    connector_name = "openx_huawei"
    source_type = "openx_huawei_listing"
    base_url = "https://arquivos.openx.com.br/Huawei/"

    def build_url(self, request: SourceFetchRequest) -> str:
        return request.params.get("url") or request.config.get("url") or self.base_url

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        url = self.build_url(request)
        timeout = int(request.params.get("timeout_seconds") or 30)
        try:
            root_html = self.get_text(url, timeout=timeout)
            root_entries = _parse_apache_index(root_html)
        except Exception as exc:
            return SourceFetchResult(
                source_name=request.source_name,
                connector_name=self.connector_name,
                metadata={"url": url},
                errors=[str(exc)],
            )

        all_items = []
        # Root page lists category directories (OLTs, Routers, Switches, ONUs)
        for name, href, date, size, is_dir in root_entries:
            if not is_dir or not href:
                continue
            category = name.rstrip("/")
            category_url = urljoin(url, href)
            try:
                sub_items = self._crawl_directory(category_url, category, "", 0, 5, timeout)
                all_items.extend(sub_items)
            except Exception as exc:
                # Log error but continue with other categories
                pass

        return SourceFetchResult(
            source_name=request.source_name,
            connector_name=self.connector_name,
            items=all_items,
            metadata={"url": url, "categories_scraped": len({i.get("category") for i in all_items})},
        )

    def _crawl_directory(
        self, url: str, category: str, subcategory: str, depth: int, max_depth: int, timeout: int
    ) -> list[dict]:
        if depth > max_depth:
            return []
        try:
            html = self.get_text(url, timeout=timeout)
        except Exception:
            return []

        entries = _parse_apache_index(html)
        results: list[dict] = []

        for name, href, date, size, is_dir in entries:
            if not href:
                continue
            full_url = urljoin(url, href)

            if is_dir:
                dirname = name.rstrip("/")
                current_sub = subcategory if subcategory else dirname
                if depth == 0:
                    current_sub = ""
                sub_results = self._crawl_directory(full_url, category, current_sub, depth + 1, max_depth, timeout)
                results.extend(sub_results)
            else:
                results.append({
                    "name": name,
                    "url": full_url,
                    "is_dir": False,
                    "source_type": "openx_huawei",
                    "category": category,
                    "subcategory": subcategory,
                    "last_modified": date,
                    "size": size if size and size != "-" else "",
                })

        return results
