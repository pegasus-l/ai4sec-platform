from __future__ import annotations

import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.domains.vulnerabilities.keyword_profiles import list_keyword_profiles
from ai4sec_platform.domains.vulnerabilities import service as vuln_service
from ai4sec_platform.services import domain_items
from ai4sec_platform.services import operations

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])
DOMAIN = "vulnerabilities"


def _compact_stage_list(conn: sqlite3.Connection, item_type: str, limit: int) -> dict:
    data = domain_items.list_items(conn, DOMAIN, item_type=item_type, limit=limit)
    data["items"] = [_compact_stage_item(item) for item in data["items"]]
    return data


def _compact_stage_item(item: dict) -> dict:
    payload = item.get("payload") or {}
    compact_payload = {
        key: payload.get(key)
        for key in ("failure_reason", "error", "attempt_count", "crawl_mode", "search_keyword", "decision", "confidence", "reason")
        if payload.get(key) is not None
    }
    return {
        key: value
        for key, value in {**item, "payload": compact_payload}.items()
        if key not in {"evidence"}
    }


class FieldReviewRequest(BaseModel):
    reviewer: str = "shadow_operator"
    value: object | None = None
    reason: str = ""
    evidence_ids: list[int] = []


@router.get("/keyword-profiles")
def keyword_profiles() -> dict:
    return {"items": list_keyword_profiles(load_settings().project_root)}


@router.get("/runs/{run_id}/results")
def run_results(run_id: str, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    run = conn.execute("SELECT summary_json FROM pipeline_runs WHERE run_id = ?", (run_id,)).fetchone()
    summary = repo.loads(run["summary_json"], {}) if run else {}
    child_run_ids = [str(value) for value in summary.get("child_run_ids") or []]
    for step in summary.get("steps") or []:
        for child_run_id in (step.get("metrics") or {}).get("child_run_ids") or []:
            if str(child_run_id) not in child_run_ids:
                child_run_ids.append(str(child_run_id))
    included_run_ids = [run_id, *child_run_ids]
    placeholders = ",".join("?" for _ in included_run_ids)
    rows = conn.execute(
        f"""
        SELECT * FROM domain_items
        WHERE domain = ? AND (
            json_extract(metrics_json, '$.pipeline_run') IN ({placeholders})
            OR EXISTS (
                SELECT 1 FROM json_each(domain_items.metrics_json, '$.pipeline_runs')
                WHERE json_each.value IN ({placeholders})
            )
        )
        ORDER BY id ASC
        """,
        (DOMAIN, *included_run_ids, *included_run_ids),
    ).fetchall()
    stages: dict[str, list[dict]] = {}
    for row in rows:
        item = _compact_stage_item(repo.row_to_dict(row))
        stages.setdefault(str(item["item_type"]), []).append(item)
    return {
        "run_id": run_id,
        "child_run_ids": child_run_ids,
        "count": len(rows),
        "stages": stages,
    }


@router.get("/runs")
def runs(limit: int = Query(20, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    rows = conn.execute(
        """
        SELECT * FROM pipeline_runs
        WHERE domain = ?
          AND COALESCE(json_extract(summary_json, '$.params.batch_parent_run_id'), '') = ''
        ORDER BY id DESC LIMIT ?
        """,
        (DOMAIN, limit),
    ).fetchall()
    items = []
    for row in rows:
        item = repo.row_to_dict(row)
        summary = item.get("summary") or {}
        item["summary"] = {
            "status": summary.get("status"),
            "error_message": summary.get("error_message"),
            "current_step": summary.get("current_step"),
            "completed_steps": summary.get("completed_steps"),
            "total_steps": summary.get("total_steps"),
            "batch_progress": summary.get("batch_progress"),
        }
        items.append(item)
    return {"items": items}


@router.get("/today")
def today(limit: int = Query(12, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return vuln_service.today(conn, limit=limit)


@router.get("/materials")
def materials(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="material", limit=limit)


@router.get("/candidates")
def candidates(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _compact_stage_list(conn, "search_candidate", limit)


@router.get("/crawled-pages")
def crawled_pages(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _compact_stage_list(conn, "crawled_page", limit)


@router.get("/extracted-content")
def extracted_content(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _compact_stage_list(conn, "extracted_content", limit)


@router.get("/material-reviews")
def material_reviews(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _compact_stage_list(conn, "material_review", limit)


@router.get("/evaluations")
def evaluations(limit: int = Query(20, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    rows = conn.execute(
        "SELECT * FROM domain_items WHERE domain = ? AND item_type = ? ORDER BY id DESC LIMIT ?",
        (DOMAIN, "shadow_evaluation", limit),
    ).fetchall()
    items = [repo.row_to_dict(row) for row in rows]
    return {"domain": DOMAIN, "count": len(items), "items": items}


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
