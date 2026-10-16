from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.vulnerabilities import cases as case_service
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

    现在只是**兜底**: 库里查不到任何跑批记录时才用它(正常情况下窗口由 _batch_window 圈)。
    2026-09-16 起这一页用的就是它, 但它的前提是"跑批 2.5-5 小时、产出落在北京 00:30-03:20";
    实际跑批时长随抓取量变, 09-18/09-19 在 22:57/22:52 就跑完了 —— 产出全在零点之前,
    于是这个窗口里一条都没有, 白天打开永远是空的(**跑得越快越空**)。
    """
    midnight_cst = datetime.now(CST).replace(hour=0, minute=0, second=0, microsecond=0)
    return f"{midnight_cst.astimezone(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"


# 素材/事件/知识只有这一条流水线在产(comprehension_probe 之类只做验证, 不产出情报)。
_BATCH_PIPELINE = "vulnerabilities.full_knowledge_discovery_pipeline"


def _to_cst(value: str | None) -> datetime | None:
    """库里的 UTC ISO 串 → 北京时间(datetime 对象); 解析不了就返回 None。"""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(CST)
    except ValueError:
        return None


def _window_payload(row: tuple, *, source: str) -> dict[str, Any]:
    run_id, started_at, finished_at, status = row
    start, end = _to_cst(started_at), _to_cst(finished_at)
    if source == "running" or end is None:
        label = f"本批({start:%m-%d %H:%M} 起, 跑批中)" if start else "本批(跑批中)"
    else:
        label = f"本批({start:%m-%d %H:%M}-{end:%H:%M})" if start else "本批"
    return {
        "since": started_at, "source": source, "label": label, "run_id": run_id,
        "started_at": started_at, "finished_at": finished_at, "status": status,
    }


def _batch_window(conn: sqlite3.Connection) -> dict[str, Any]:
    """今日情报的窗口 = **最近一批跑批**的开始时间, 而不是日历上的"今天零点"。

    2026-09-20 的改动: 按日历切会把"跑得快"变成一个 bug —— 09-18/09-19 两晚都在北京零点
    之前跑完, 产出落进"昨天", 这一页整天为空。按"上一批"圈窗口后, 这一页显示的就是最近
    一批的产出, 与跑批耗时无关。
    优先取**正在跑的那批**(跑批过程中页面跟着长); 没有在跑的, 取最近一次**成功**的批次。
    失败/中断的批次不当窗口(它们可能只跑了几分钟, 按它们切会让页面近乎清空) —— 这条规则
    顺带就是兜底: 今晚跑挂了, 页面退回昨天那批, 而不会变空。
    """
    running = conn.execute(
        "SELECT run_id, started_at, finished_at, status FROM pipeline_runs "
        "WHERE pipeline_name = ? AND started_at IS NOT NULL AND finished_at IS NULL "
        "ORDER BY started_at DESC LIMIT 1",
        (_BATCH_PIPELINE,),
    ).fetchone()
    if running is not None:
        started = _to_cst(running[1])
        # 兜底: 疑似僵尸 running(重启打断后没被启动恢复收掉)不认, 否则窗口会被它永久钉住。
        if started is not None and (datetime.now(CST) - started) <= timedelta(hours=12):
            return _window_payload(running, source="running")
    done = conn.execute(
        "SELECT run_id, started_at, finished_at, status FROM pipeline_runs "
        "WHERE pipeline_name = ? AND status = 'success' AND started_at IS NOT NULL AND finished_at IS NOT NULL "
        "ORDER BY finished_at DESC LIMIT 1",
        (_BATCH_PIPELINE,),
    ).fetchone()
    if done is not None:
        return _window_payload(done, source="batch")
    return {
        "since": _today_start(), "source": "calendar", "label": "当天零点(北京时间)",
        "run_id": None, "started_at": None, "finished_at": None, "status": None,
    }


def materials(conn: sqlite3.Connection, *, limit: int = 50, q: str | None = None,
              chip: str | None = None, sort: str | None = None,
              page: int | None = None, page_size: int | None = None) -> dict:
    """素材列表: 筛选(芯片 + 搜索)、排序、分页全部下推到 SQL。

    2026-09-17 之前这里只吃 limit, 上限 200 —— 库里有 313 条非「已淘汰」素材, 于是分数最低的
    113 条在页面上永远不可达(且因为排序是分数优先, 被砍掉的根本不是"旧素材")。
    现在筛选谓词与 chip_counts 共用 db.repositories 里同一批常量, 所以「芯片上的数字」与
    「列表里的条数」结构性同源; 未知 sort 由 repo 报错、未知 chip 由路由报 400, 都不静默忽略。
    """
    data = domain_items.list_items(
        conn, DOMAIN, item_type="material", limit=limit, q=q,
        # "all" 是全量口径(1=1), 不必真下一个恒真条件
        material_chips=[chip] if chip and chip != "all" else None,
        haystack="material", sort=sort, page=page, page_size=page_size,
    )
    data["items"] = [slim_material(item) for item in data["items"]]
    data["chip_counts"] = repo.material_chip_counts(conn, DOMAIN)
    return data


def today(conn: sqlite3.Connection, limit: int = 12) -> dict[str, Any]:
    # 今日情报 = 最近一批跑批(或正在跑的那批)产出的素材/事件/知识, 见 _batch_window
    window = _batch_window(conn)
    batch_start = window["since"]
    materials_data = domain_items.list_items(conn, DOMAIN, item_type="material", limit=limit, since=batch_start)
    materials_data["items"] = [slim_material(item) for item in materials_data["items"]]
    events_data = _active_events(conn, limit, since=batch_start)
    knowledge_data = domain_items.list_items(conn, DOMAIN, item_type="knowledge", limit=limit, since=batch_start)
    # 案例库(2026-10-16):「漏洞事件库」改成以洞为主键的案例库后, 这一页的主卡片从"事件"换成"案例"。
    # 窗口不变 —— 同一条 _batch_window, 所以"这批新登记了哪些洞"与其他两张卡口径一致。
    # 旧 event 现在全是 superseded, events_data 恒空; 那两行**保留不删**: 键删掉老前端会渲染空白
    # (P0 同样的理由), 且回滚时把 event 的 status 改回 active 就恢复。
    cases_data = case_service.list_cases(conn, created_since=batch_start, limit=limit)
    return {
        "domain": DOMAIN,
        # 窗口自述: 前端用它说明"这一页是哪一批", 免得再出现"空了但不知道为什么"
        "window": window,
        "kpis": {
            "new_poc_count": sum(1 for item in materials_data["items"] if (item.get("payload") or {}).get("material_type") == "poc_exploit"),
            "new_or_updated_event_count": len(events_data["items"]),
            # 新口径(2026-10-16): 这批新入库的**漏洞案例**数(人工添加的 pending_fetch 也算 ——
            # 登记了就是登记了, 抓不抓得到元数据是下一步的事)。
            # 用 total(窗口内的真实计数)而不是 len(items): items 受 limit 截断, 拿它当计数会在
            # 批量入库的那天恰好等于 limit —— 2026-09-11 那批 1351 条的教训, 数字必须与截断解耦。
            "new_case_count": int(cases_data.get("total") or 0),
            "case_total": int(case_service.case_stats(conn)["total"]),
            # 逐字段人工确认 2026-10-16 下线(前端页面已撤, 队列也不再写), 计数恒 0。
            # 键**保留**: 老前端/脚本读到 undefined 会渲染成空白而不是 0, 删字段等于制造一次静默故障。
            "pending_field_review_count": 0,
            # 新口径: 这批知识抽取出来多少条(供模式合成消费), 才是运营真正关心的数
            "knowledge_count": len(knowledge_data["items"]),
            "confirmed_knowledge_count": sum(1 for item in knowledge_data["items"] if item.get("status") == "confirmed"),
        },
        "workflow": ["先看新 PoC / Exploit", "按 CVE 归并到漏洞案例", "模型自动抽取知识字段", "沉淀到漏洞模式库"],
        # 旧事件键保留(见上方注释); 新键 new_cases 是本批新增的案例, 前端主卡片读它。
        "priority_events": [_event_card(item) for item in events_data["items"]],
        "priority_event_items": events_data["items"],
        "new_cases": cases_data["items"],
        "new_materials": materials_data["items"],
        "new_knowledge": knowledge_data["items"],
        "items": materials_data["items"],
        "next_workload": {"materials": len(materials_data["items"]), "events": len(events_data["items"]), "cases": len(cases_data["items"]), "pending_fields": 0, "knowledge": len(knowledge_data["items"])},
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
