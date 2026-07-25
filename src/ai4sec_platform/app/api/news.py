from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Query

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.domains.news import operations as news_operations, service
from ai4sec_platform.domains.news.schemas import NewsActionRequest
from ai4sec_platform.domains.news.tech_map import AgentTechMap
from ai4sec_platform.core.config import PROJECT_ROOT
from ai4sec_platform.services import operations

router = APIRouter(prefix="/news", tags=["news"])


@router.get("/ops/overview")
def ops_overview(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return news_operations.overview(conn)


@router.get("/ops/runs")
def ops_runs(limit: int = Query(30, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return {"items": news_operations.list_runs(conn, limit=limit)}


@router.get("/ops/runs/{run_id}")
def ops_run_detail(run_id: str, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    result = news_operations.run_detail(conn, run_id)
    if not result:
        raise HTTPException(status_code=404, detail="news pipeline run not found")
    return result


@router.get("/ops/sources")
def ops_sources(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return {"items": news_operations.source_status(conn)}


@router.get("/ops/quality")
def ops_quality(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return news_operations.quality(conn)


@router.get("/today")
def today(limit: int = Query(12, ge=1, le=100), operator: str = Query("operator"), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return service.today(conn, limit=limit, operator=operator)


@router.get("/items")
def items(query: str = "", item_type: str = "", source: str = "", topic: str = "", tech_dimension: list[str] = Query(default=[]), tech_category: list[str] = Query(default=[]), tech_point: list[str] = Query(default=[]), tech_match: str = Query("any", pattern="^(any|all)$"), status: str = "", date_from: str = "", date_to: str = "", min_score: float | None = Query(None, ge=0, le=100), sort: str = "score", page: int = Query(1, ge=1), page_size: int = Query(30, ge=1, le=100), operator: str = "operator", conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return service.list_news(conn, query=query, item_type=item_type, source=source, topic=topic, tech_dimensions=tech_dimension, tech_categories=tech_category, tech_points=tech_point, tech_match=tech_match, status=status, date_from=date_from, date_to=date_to, min_score=min_score, sort=sort, page=page, page_size=page_size, operator=operator)


@router.get("/items/{item_id}")
def item_detail(item_id: int, operator: str = "operator", conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = service.detail(conn, item_id, operator)
    if not item:
        raise HTTPException(status_code=404, detail="news item not found")
    return item


@router.get("/reports")
def reports(limit: int = Query(30, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return service.reports(conn, limit=limit)


@router.get("/reports/{report_date}")
def report_detail(report_date: str, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    report = service.report_detail(conn, report_date)
    if not report:
        raise HTTPException(status_code=404, detail="news report not found")
    return report


@router.get("/topics")
def topics(limit: int = Query(30, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return {"domain": "news", "items": service.topic_summary(conn, limit=limit)}


@router.get("/topics/{topic}")
def topic_detail(topic: str, operator: str = "operator", conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return service.topic_detail(conn, topic, operator=operator)


@router.get("/sources")
def sources(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return {"domain": "news", "items": service.source_summary(conn)}


@router.get("/tech-map")
def tech_map(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    taxonomy = AgentTechMap.load(PROJECT_ROOT)
    counts = service.tech_path_counts(conn)
    items = [{**path, "count": counts.get((path["dimension"], path["category"], path["point"]), 0)} for path in taxonomy.catalog()]
    return {"domain": "news", "name": taxonomy.name, "version": taxonomy.version, "items": items}


@router.post("/items/{item_id}/read")
def mark_read(item_id: int, request: NewsActionRequest | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _action(conn, item_id, "read", request)


@router.post("/items/{item_id}/bookmark")
def bookmark(item_id: int, request: NewsActionRequest | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _action(conn, item_id, "bookmark", request)


@router.post("/items/{item_id}/later")
def later(item_id: int, request: NewsActionRequest | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _action(conn, item_id, "later", request)


@router.post("/items/{item_id}/ignore")
def ignore(item_id: int, request: NewsActionRequest | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _action(conn, item_id, "ignore", request)


@router.post("/items/{item_id}/unignore")
def unignore(item_id: int, request: NewsActionRequest | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _action(conn, item_id, "unignore", request)


@router.post("/items/{item_id}/feedback")
def feedback(item_id: int, request: NewsActionRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _action(conn, item_id, "feedback", request)


@router.post("/items/{item_id}/promote-to-capability")
def promote(item_id: int, request: NewsActionRequest | None = None, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    result = service.promote_to_capability(conn, item_id, operator=(request.operator if request else "operator"))
    if not result:
        raise HTTPException(status_code=404, detail="news item not found")
    conn.commit()
    return result


@router.get("/operations")
def news_operations(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return {"domain": "news", "tasks": operations.tasks(conn, "news")["items"], "sources": operations.sources(conn, "news")["items"], "audits": operations.audits(conn, "news")["items"]}


@router.get("/page")
def page() -> dict:
    return {"domain": "news", "title": "资讯洞察", "description": "从多源采集、筛选和阅读 AI 安全资讯。", "tabs": ["今日精选", "全部动态", "日报", "专题时间线"]}


def _action(conn: sqlite3.Connection, item_id: int, action: str, request: NewsActionRequest | None) -> dict:
    request = request or NewsActionRequest()
    result = service.apply_action(conn, item_id, action, operator=request.operator, value=request.value, reason=request.reason)
    if not result:
        raise HTTPException(status_code=404, detail="news item not found")
    conn.commit()
    return {"item_id": item_id, "action": action, "user_state": result}
