from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.vulnerabilities import field_reviews
from ai4sec_platform.services import domain_items

DOMAIN = "vulnerabilities"

# 北京时间。调度和产出都按北京作息走, 但库里 created_at 存的是 UTC,
# 所以"今日"的边界要在这里换算, 不能直接拿 UTC 零点当边界(见 _today_start)。
CST = timezone(timedelta(hours=8))

# 列表/卡片接口只承载"识别结果 + 归并依据"。下面这些键 200 条列表实测合计 129MB 裸
# (整页原文 raw 992KB / images 404KB / markdown 133KB / cleaned_text 125KB / links 61KB
#  逐条打头, 后面还有 review、content_extraction 等中间产物), 过隧道要 8s+,
# 而前端在数据到达前先渲染空态, 看起来就像"素材全没了"。
# 这些键漏洞洞察的前端一个都不读(已逐一 grep 确认): 正文与中间产物仍由
# /materials/{id} 详情与下载接口按需直读, 后端流水线读的是库不是本响应, 均不受影响。
_HEAVY_PAYLOAD_KEYS = (
    # 整页原文
    "raw", "images", "markdown", "cleaned_text", "links",
    # 抓取/抽取中间产物: 只服务于下游流水线, 页面只看结论字段(check_reason/reason/key_findings)
    "review", "content_extraction", "knowledge_extraction",
    "extracted_evidence", "crawl_info", "metadata", "entity_mentions",
)


def slim_material(item: dict[str, Any]) -> dict[str, Any]:
    """就地剥掉素材 payload 里的整页原文, 供列表类接口使用(详情/下载不走这里)。"""
    payload = item.get("payload")
    if isinstance(payload, dict):
        for key in _HEAVY_PAYLOAD_KEYS:
            payload.pop(key, None)
    return item


def _today_start() -> str:
    """今日起点 = 北京时间零点, 换算成 UTC 的 ISO 串(与 created_at 存储格式一致, 可直接字符串比较)。

    流水线每天 14:00Z(=北京 22:00)起跑、跑 2.5-5 小时, 产出落在 16:30-19:20Z
    = 北京次日 00:30-03:20。按 UTC 零点切的话这批产出会被算进"UTC 昨天":
    北京 08:00-24:00 打开"今日"永远是空的, 只有凌晨那段窗口才有内容。
    按北京零点切, 白天打开就能看到当晚那批。
    """
    midnight_cst = datetime.now(CST).replace(hour=0, minute=0, second=0, microsecond=0)
    return f"{midnight_cst.astimezone(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"


def materials(conn: sqlite3.Connection, limit: int = 50) -> dict:
    data = domain_items.list_items(conn, DOMAIN, item_type="material", limit=limit)
    data["items"] = [slim_material(item) for item in data["items"]]
    return data


def today(conn: sqlite3.Connection, limit: int = 12) -> dict[str, Any]:
    # 今日情报 = 北京时间当天零点之后产出的素材/事件/知识
    today_start = _today_start()
    materials_data = domain_items.list_items(conn, DOMAIN, item_type="material", limit=limit, since=today_start)
    materials_data["items"] = [slim_material(item) for item in materials_data["items"]]
    events_data = _active_events(conn, limit, since=today_start)
    knowledge_data = domain_items.list_items(conn, DOMAIN, item_type="knowledge", limit=limit, since=today_start)
    pending_fields = _pending_field_count(knowledge_data["items"])
    return {
        "domain": DOMAIN,
        "kpis": {
            "new_poc_count": sum(1 for item in materials_data["items"] if (item.get("payload") or {}).get("material_type") == "poc_exploit"),
            "new_or_updated_event_count": len(events_data["items"]),
            "pending_field_review_count": pending_fields,
            "confirmed_knowledge_count": sum(1 for item in knowledge_data["items"] if item.get("status") == "confirmed"),
        },
        "workflow": ["先看新 PoC / Exploit", "按 CVE / 事件归并", "复核知识字段", "沉淀到知识库"],
        "priority_events": [_event_card(item) for item in events_data["items"]],
        "priority_event_items": events_data["items"],
        "new_materials": materials_data["items"],
        "new_knowledge": knowledge_data["items"],
        "items": materials_data["items"],
        "next_workload": {"materials": len(materials_data["items"]), "events": len(events_data["items"]), "pending_fields": pending_fields, "knowledge": len(knowledge_data["items"])},
    }


def events(conn: sqlite3.Connection, limit: int = 50) -> dict[str, Any]:
    return _active_events(conn, limit)


def _active_events(conn: sqlite3.Connection, limit: int, since: str | None = None) -> dict[str, Any]:
    data = domain_items.list_items(conn, DOMAIN, item_type="event", limit=max(limit * 3, limit), since=since)
    items = [item for item in data["items"] if item.get("status") != "superseded"][:limit]
    return {"domain": DOMAIN, "count": len(items), "items": items}


def event_detail(conn: sqlite3.Connection, item_id: int) -> dict[str, Any] | None:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "event":
        return None
    material_ids = (item.get("payload") or {}).get("material_ids") or []
    materials_for_event = []
    for material_id in material_ids:
        material = domain_items.detail(conn, DOMAIN, int(material_id))
        if material:
            # 事件抽屉只展示素材的标题/类型/来源, 同样不需要整页原文
            materials_for_event.append(slim_material(material))
    item["materials"] = materials_for_event
    return item


def extractions(conn: sqlite3.Connection, limit: int = 50) -> dict[str, Any]:
    data = domain_items.list_items(conn, DOMAIN, item_type="knowledge", limit=limit)
    items = []
    for item in data["items"]:
        payload = item.get("payload") or {}
        items.append({**item, "field_reviews": payload.get("field_reviews") or {}, "pending_field_count": _pending_field_count([item])})
    return {"domain": DOMAIN, "count": len(items), "items": items}


def accept_field(conn: sqlite3.Connection, knowledge_id: int, field_name: str, reviewer: str = "shadow_operator", reason: str = "") -> dict[str, Any]:
    return field_reviews.accept_field(conn, knowledge_id, field_name, reviewer=reviewer, reason=reason)


def modify_field(conn: sqlite3.Connection, knowledge_id: int, field_name: str, value: Any, reviewer: str = "shadow_operator", reason: str = "") -> dict[str, Any]:
    return field_reviews.modify_field(conn, knowledge_id, field_name, value, reviewer=reviewer, reason=reason)


def reject_field(conn: sqlite3.Connection, knowledge_id: int, field_name: str, reviewer: str = "shadow_operator", reason: str = "") -> dict[str, Any]:
    return field_reviews.reject_field(conn, knowledge_id, field_name, reviewer=reviewer, reason=reason)


def _event_card(item: dict[str, Any]) -> dict[str, Any]:
    payload = item.get("payload") or {}
    return {
        "item_id": item.get("id"),
        "event_id": payload.get("event_id"),
        "title": item.get("title"),
        "kind": payload.get("kind"),
        "primary_cve_id": payload.get("primary_cve_id"),
        "cve_ids": payload.get("cve_ids") or [],
        "cwe_ids": payload.get("cwe_ids") or [],
        "status": item.get("status"),
        "score": item.get("score"),
        "material_count": len(payload.get("material_ids") or []),
        "knowledge_completeness": payload.get("knowledge_completeness", 0),
        "next_action": "复核事件归并" if payload.get("kind") in {"multi_cve_event", "knowledge_topic"} else "进入知识抽取",
    }


def _pending_field_count(items: list[dict[str, Any]]) -> int:
    count = 0
    for item in items:
        reviews = (item.get("payload") or {}).get("field_reviews") or {}
        count += sum(1 for review in reviews.values() if review.get("status") not in {"accepted", "modified"})
    return count
