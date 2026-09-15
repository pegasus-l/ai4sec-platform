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

# 能力卡搜索覆盖的 payload 展示字段(标题/工作名/话题/一句话/概述/摘要/仓库)。
# 清单唯一真源在 db.repositories.CAP_SEARCH_PAYLOAD_KEYS —— SQL 侧(cap_haystack_sql)也用它,
# 两边同一份, 加字段时不会一边加一边漏。
_SEARCH_PAYLOAD_KEYS = repo.CAP_SEARCH_PAYLOAD_KEYS


def _item_matches_q(item: dict[str, Any], q: str) -> bool:
    """能力卡搜索匹配的 Python 参照实现: 覆盖标题/摘要/来源/展示字段/技术点, 不区分大小写。

    2026-09-15 起线上列表已走 SQL 侧同一判据(db.repositories.search_predicate / cap_haystack_sql,
    有等价性实测)。本函数保留为「参照实现」(也是差分测试的 oracle): 改搜索口径时两边必须一起改。
    注意 SQL 侧是刻意复刻本函数 `" ".join(parts)` 的拼接语义(所以跨字段组合词同样能命中)。
    """
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
               q: str | None = None, page: int | None = None, page_size: int | None = None,
               since: str | None = None, forms: list[str] | None = None,
               repro_chips: list[str] | None = None) -> dict[str, Any]:
    """列能力卡。支持搜索(q)、芯片筛选(forms/repro_chips)与分页(page/page_size)。

    2026-09-15 起: 给了 q/forms/repro_chips/page 就走「SQL 过滤 + LIMIT/OFFSET + COUNT(*)」。
    此前是 fetch_limit=10000, 把全部行连完整 payload 拉进 Python 再过滤、切片 —— 服务端开销
    (0.48s)和响应体积(10.2MB 裸 / 1.39MB gz)都下不来, 前端那个「分页」实际发生在下载完之后。
    筛选谓词与 /items/stats 的芯片计数共用 db.repositories 里同一批常量, 两者结构性同源。
    不带这些参数时保持旧路径(其它域调用方零影响)。
    since: created_at 时间下界(ISO-8601 UTC), 如「今日零点」→ 只返回该时刻之后产出的条目。
    返回: {domain, label, count, total, page, page_size, items}; total = 命中总数(精确计数)。
    """
    q = (q or "").strip()
    forms = [f for f in (forms or []) if f]
    repro_chips = [c for c in (repro_chips or []) if c]
    if q or forms or repro_chips or page is not None:
        eff_limit, offset = limit, 0
        if page is not None and page_size is not None and page_size > 0:
            eff_limit = page_size
            offset = (page - 1) * page_size
        paged = repo.list_domain_items(conn, domain, item_type=item_type, limit=eff_limit, offset=offset,
                                       exclude_status="已淘汰", since=since,
                                       forms=forms, repro_chips=repro_chips, q=q)
        total = repo.count_domain_items(conn, domain, item_type=item_type, exclude_status="已淘汰",
                                        since=since, forms=forms, repro_chips=repro_chips, q=q)
    else:
        items = repo.list_domain_items(conn, domain, item_type=item_type, limit=limit,
                                       exclude_status="已淘汰", since=since)
        paged = items
        total = len(items)
    return {
        "domain": domain,
        "label": DOMAIN_LABELS.get(domain, domain),
        "count": len(paged),
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": paged,
    }


def today(conn: sqlite3.Connection, domain: str, *, limit: int = 12, since: str | None = None) -> dict[str, Any]:
    return list_items(conn, domain, item_type=TODAY_ITEM_TYPES.get(domain), limit=limit, since=since)


def filter_stats(conn: sqlite3.Connection, domain: str) -> dict[str, Any]:
    """能力库筛选统计:全量 SQL 聚合,不受 /items 的 limit 窗口影响。与列表同人口。"""
    return repo.filter_stats_by_domain(conn, domain)


def detail(conn: sqlite3.Connection, domain: str, item_id: int) -> dict[str, Any] | None:
    return repo.get_domain_item(conn, domain, item_id)
