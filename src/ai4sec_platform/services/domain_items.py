from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo

DOMAIN_LABELS = {
    "news": "资讯洞察",
    "capabilities": "能力洞察",
    "threats": "威胁洞察",
    "vulnerabilities": "漏洞洞察",
}

TODAY_ITEM_TYPES = {
    "news": None,
    "capabilities": "capability",
    "threats": "target",
    "vulnerabilities": "material",
}

# 能力卡搜索覆盖的 payload 展示字段(标题/工作名/话题/一句话/概述/摘要/仓库)
_SEARCH_PAYLOAD_KEYS = (
    "display_title", "display_work_name", "display_topic", "one_liner", "overview",
    "summary", "code_url",
)


def _item_matches_q(item: dict[str, Any], q: str) -> bool:
    """能力卡搜索匹配: 覆盖标题/摘要/来源/展示字段/技术点, 不区分大小写。"""
    ql = q.lower()
    parts = [
        str(item.get("title") or ""),
        str(item.get("summary") or ""),
        str(item.get("source_url") or ""),
    ]
    p = item.get("payload") or {}
    for key in _SEARCH_PAYLOAD_KEYS:
        val = p.get(key)
        if val:
            parts.append(str(val))
    tp = p.get("tech_points")
    if isinstance(tp, list):
        parts.append(" ".join(str(x) for x in tp))
    elif tp:
        parts.append(str(tp))
    return ql in " ".join(parts).lower()


def list_items(conn: sqlite3.Connection, domain: str, *, item_type: str | None = None, limit: int = 50,
               q: str | None = None, page: int | None = None, page_size: int | None = None) -> dict[str, Any]:
    """列能力卡。支持搜索(q)与分页(page/page_size 同时给出时启用)。

    搜索/分页需要覆盖全量数据做过滤, 不走搜索时按原 limit 截取。
    返回: {domain, label, count, total, page, page_size, items}
    """
    fetch_limit = limit
    if q or page is not None:
        fetch_limit = 10000
    items = repo.list_domain_items(conn, domain, item_type=item_type, limit=fetch_limit, exclude_status="已淘汰")
    q = (q or "").strip()
    if q:
        items = [it for it in items if _item_matches_q(it, q)]
    total = len(items)
    if page is not None and page_size is not None and page_size > 0:
        start = (page - 1) * page_size
        paged = items[start:start + page_size]
    else:
        paged = items
    return {
        "domain": domain,
        "label": DOMAIN_LABELS.get(domain, domain),
        "count": len(paged),
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": paged,
    }


def today(conn: sqlite3.Connection, domain: str, *, limit: int = 12) -> dict[str, Any]:
    return list_items(conn, domain, item_type=TODAY_ITEM_TYPES.get(domain), limit=limit)


def detail(conn: sqlite3.Connection, domain: str, item_id: int) -> dict[str, Any] | None:
    return repo.get_domain_item(conn, domain, item_id)
