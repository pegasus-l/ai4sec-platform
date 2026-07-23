from __future__ import annotations

import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.domains.vulnerabilities import service as vuln_service
from ai4sec_platform.services import domain_items
from ai4sec_platform.services import operations

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])
DOMAIN = "vulnerabilities"


class FieldReviewRequest(BaseModel):
    reviewer: str = "shadow_operator"
    value: object | None = None
    reason: str = ""
    evidence_ids: list[int] = []


@router.get("/today")
def today(limit: int = Query(12, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return vuln_service.today(conn, limit=limit)


@router.get("/materials")
def materials(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="material", limit=limit)


@router.get("/candidates")
def candidates(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="search_candidate", limit=limit)


@router.get("/crawled-pages")
def crawled_pages(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="crawled_page", limit=limit)


@router.get("/material-reviews")
def material_reviews(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="material_review", limit=limit)


@router.get("/materials/{item_id}")
def material_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="material not found")
    return item


@router.get("/events")
def events(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return vuln_service.events(conn, limit=limit)


@router.get("/events/{item_id}")
def event_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = vuln_service.event_detail(conn, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="event not found")
    return item


@router.get("/extractions")
def extractions(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return vuln_service.extractions(conn, limit=limit)


@router.get("/knowledge")
def knowledge(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    data = domain_items.list_items(conn, DOMAIN, item_type="knowledge", limit=50)
    return {
        "domain": DOMAIN,
        "items": [
            {
                "item_id": item["id"],
                "title": item["title"],
                "status": item["status"],
                "summary": item.get("summary", ""),
                "source_material_id": item.get("payload", {}).get("source_material_id"),
                "key_findings": item.get("payload", {}).get("key_findings", []),
                "verification_clues": item.get("payload", {}).get("verification_clues", []),
            }
            for item in data["items"]
        ],
    }


@router.get("/knowledge/{item_id}")
def knowledge_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "knowledge":
        raise HTTPException(status_code=404, detail="knowledge not found")
    return item


@router.get("/knowledge/{item_id}/model-snippet")
def knowledge_model_snippet(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "knowledge":
        raise HTTPException(status_code=404, detail="knowledge not found")
    payload = item.get("payload") or {}
    snippet = "\n".join(
        [
            f"【漏洞类型】{payload.get('vulnerability_type', '')}",
            f"【CVE】{', '.join(payload.get('cve_ids') or [])}",
            f"【CWE】{', '.join(payload.get('cwe_ids') or [])}",
            f"【根因】{payload.get('root_cause_pattern', '')}",
            f"【触发条件】{payload.get('trigger_condition', '')}",
            f"【攻击入口】{payload.get('attack_entry', '')}",
            f"【关键函数/API】{', '.join(payload.get('key_functions_or_apis') or [])}",
            f"【修复策略】{payload.get('mitigation_or_fix', '')}",
        ]
    )
    return {"knowledge_id": item_id, "title": item.get("title"), "snippet": snippet}


@router.post("/knowledge/{item_id}/fields/{field_name}/accept")
def accept_field(item_id: int, field_name: str, request: FieldReviewRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return vuln_service.accept_field(conn, item_id, field_name, reviewer=request.reviewer, reason=request.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/knowledge/{item_id}/fields/{field_name}/modify")
def modify_field(item_id: int, field_name: str, request: FieldReviewRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return vuln_service.modify_field(conn, item_id, field_name, request.value, reviewer=request.reviewer, reason=request.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/knowledge/{item_id}/fields/{field_name}/reject")
def reject_field(item_id: int, field_name: str, request: FieldReviewRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return vuln_service.reject_field(conn, item_id, field_name, reviewer=request.reviewer, reason=request.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/migration-queue")
def migration_queue(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.human_queue(conn, DOMAIN)
