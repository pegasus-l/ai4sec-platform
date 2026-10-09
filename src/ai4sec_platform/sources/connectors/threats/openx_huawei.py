from __future__ import annotations

import html
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin
from typing import List, Tuple

from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.threats.base_live import LiveJsonConnector
from ai4sec_platform.sources.result import SourceFetchResult


class _ApacheIndexParser(HTMLParser):
    """Parse Apache directory listing HTML to extract file entries.

    仅作为兜底保留:站点 2026 年改版后目录页已换成自研浏览器页(见 _parse_browse_items),
    旧的 /Huawei/ 自动索引现在直接 403。若站点回滚到老版式,这条路径仍然可用。
    """

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


# --------------------------------------------------------------------------
# 站点改版后的浏览页解析(2026-10-09)
#
# 新页面每一行是一个 <a class="item" href=... data-kind="folder|..." data-modified="<unix 秒>">,
# 名字在 <div class="item-name"> 里,大小/类型在 <div class="item-type"> 里("Firmware / imagem • 206,7 MB")。
# 目录项的 href 指回浏览页(/browse/Huawei/OLTs/),文件项的 href 仍指向根下的老路径
# (/Huawei/OLTs/xxx.bin)—— 也就是说目录索引被站点关了,文件本体照样能下。
# --------------------------------------------------------------------------

_BROWSE_ITEM_RE = re.compile(r'<a\s+class="item"(?P<attrs>[^>]*)>(?P<body>.*?)</a>', re.S)
_ATTR_RE = re.compile(r'([\w\-]+)="([^"]*)"')
# item-type 文本形如 "Firmware / imagem • 206,7 MB" / "Arquivo • 1,16 MB";
# 分隔符有的是字面 • 有的是 HTML 实体,所以不用切分,直接抓结尾的"数字+单位"。
_SIZE_RE = re.compile(r"([\d.,]+\s*(?:B|KB|MB|GB|TB))\s*$")


def _class_text(fragment: str, class_name: str) -> str:
    match = re.search(r'<div\s+class="%s">(.*?)</div>' % re.escape(class_name), fragment, re.S)
    if not match:
        return ""
    return html.unescape(re.sub(r"<[^>]+>", "", match.group(1))).strip()


def _extract_size(type_text: str) -> str:
    match = _SIZE_RE.search(type_text)
    return match.group(1).strip() if match else ""


def _epoch_to_iso(value: str) -> str:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return ""


def _parse_browse_items(html: str) -> List[dict]:
    """解析改版后的浏览页,返回 [{name, href, is_dir, kind, size, modified}]。"""
    items: List[dict] = []
    for match in _BROWSE_ITEM_RE.finditer(html):
        attrs = dict(_ATTR_RE.findall(match.group("attrs")))
        href = (attrs.get("href") or "").strip()
        if not href:
            continue
        body = match.group("body")
        kind = attrs.get("data-kind", "")
        size = _extract_size(_class_text(body, "item-type"))
        name = _class_text(body, "item-name") or (attrs.get("data-name") or "").strip()
        items.append(
            {
                "name": name or href.rstrip("/").rsplit("/", 1)[-1],
                "href": href,
                "is_dir": kind == "folder" or href.endswith("/"),
                "kind": kind,
                "size": size,
                "modified": _epoch_to_iso(attrs.get("data-modified", "")),
            }
        )
    return items


_MAX_DEPTH = 5


class OpenXHuaweiConnector(LiveJsonConnector):
    connector_name = "openx_huawei"
    source_type = "openx_huawei_listing"
    # 2026-10-09:站点把目录页从 Apache 自动索引(/Huawei/)换成了自研浏览器页(/browse/Huawei/),
    # 老路径现在直接 403。入口改指新页面,解析走 _parse_browse_items。
    base_url = "https://arquivos.openx.com.br/browse/Huawei/"

    def request_headers(self) -> dict[str, str]:
        # 只影响本连接器:get_text 会把 Accept 覆盖成 text/html,这里补一个常规浏览器 UA。
        return {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
            )
        }

    def build_url(self, request: SourceFetchRequest) -> str:
        return request.params.get("url") or request.config.get("url") or self.base_url

    def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
        url = self.build_url(request)
        timeout = int(request.params.get("timeout_seconds") or 30)
        try:
            root_html = self.get_text(url, timeout=timeout)
        except Exception as exc:
            return SourceFetchResult(
                source_name=request.source_name,
                connector_name=self.connector_name,
                metadata={"url": url},
                errors=[str(exc)],
            )

        if _parse_browse_items(root_html):
            mode = "browse"
            root_entries: List[object] = _parse_browse_items(root_html)
            crawl = self._crawl_browse
        else:
            # 兜底:站点若回滚成老版式,退回 Apache 自动索引解析
            mode = "apache"
            root_entries = _parse_apache_index(root_html)
            crawl = self._crawl_directory

        all_items: List[dict] = []
        for entry in root_entries:
            if isinstance(entry, dict):
                name, href, is_dir = entry["name"], entry["href"], entry["is_dir"]
            else:
                name, href, _date, _size, is_dir = entry
            if not is_dir or not href:
                continue
            category = str(name).rstrip("/")
            category_url = urljoin(url, href)
            try:
                all_items.extend(crawl(category_url, category, "", 0, _MAX_DEPTH, timeout))
            except Exception:
                # 单个分类失败不影响其它分类(与旧实现一致:不记 error,继续下一个)
                pass

        return SourceFetchResult(
            source_name=request.source_name,
            connector_name=self.connector_name,
            items=all_items,
            metadata={
                "url": url,
                "mode": mode,
                "categories_scraped": len({i.get("category") for i in all_items}),
            },
        )

    def _crawl_browse(
        self, url: str, category: str, subcategory: str, depth: int, max_depth: int, timeout: int
    ) -> list[dict]:
        """改版后的浏览页递归:目录 href 指回 /browse/...,文件 href 指 /Huawei/... 老路径。"""
        if depth > max_depth:
            return []
        try:
            html = self.get_text(url, timeout=timeout)
        except Exception:
            return []

        results: list[dict] = []
        for entry in _parse_browse_items(html):
            href = entry["href"]
            if entry["is_dir"]:
                dirname = entry["name"].rstrip("/")
                child_category = dirname if depth == 0 else category
                child_sub = "" if depth == 0 else (subcategory or dirname)
                results.extend(
                    self._crawl_browse(
                        urljoin(url, href), child_category, child_sub, depth + 1, max_depth, timeout
                    )
                )
            else:
                results.append(
                    {
                        "name": entry["name"],
                        "url": urljoin(url, href),
                        "is_dir": False,
                        "source_type": "openx_huawei",
                        "category": category,
                        "subcategory": subcategory,
                        "last_modified": entry["modified"],
                        "size": entry["size"],
                    }
                )
        return results

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
