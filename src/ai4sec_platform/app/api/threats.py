from __future__ import annotations

import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Query

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.domains.threats import service as threat_service
from ai4sec_platform.services import domain_items
from ai4sec_platform.services import operations
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.models.router import LLMRouter
from ai4sec_platform.pipelines.steps.threat_risk import _semantic_review_prompt, _semantic_review_payload, _build_assessment

router = APIRouter(prefix="/threats", tags=["threats"])
DOMAIN = "threats"


@router.get("/today")
def today(limit: int = Query(12, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.today(conn, DOMAIN, limit=limit)


@router.get("/targets")
def targets(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="target", limit=limit)


@router.get("/targets/{item_id}")
def target_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="target not found")
    return item


@router.get("/tracking-queue")
def tracking_queue(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.human_queue(conn, DOMAIN)


@router.get("/audits")
def audits(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.audits(conn, DOMAIN)


@router.get("/tracking")
def tracking(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.human_queue(conn, DOMAIN)


@router.get("/risk-assessments")
def risk_assessments(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    data = domain_items.list_items(conn, DOMAIN, item_type="target", limit=limit)
    return {
        "domain": DOMAIN,
        "items": [
            {
                "item_id": item["id"],
                "title": item["title"],
                "status": item["status"],
                "score": item.get("score"),
                "risk_assessment": item.get("payload", {}).get("risk_assessment", {}),
            }
            for item in data["items"]
            if item.get("payload", {}).get("risk_assessment")
        ],
    }


@router.get("/assets")
def assets(limit: int = Query(100, ge=1, le=300), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="asset", limit=limit)


@router.get("/cve-scout")
def cve_scout(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return threat_service.latest_artifact_preview(conn, "huawei_cve_scout")


@router.get("/attack-surface")
def attack_surface(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return threat_service.latest_artifact_preview(conn, "huawei_attack_surface")


@router.get("/reports")
def reports(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return threat_service.latest_artifact_preview(conn, "huawei_threat_report")


@router.get("/graph")
def graph(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    targets_data = domain_items.list_items(conn, DOMAIN, item_type="target", limit=100)
    nodes = [
        {"id": f"target:{item['id']}", "label": item["title"], "type": "target", "score": item.get("score")}
        for item in targets_data["items"]
    ]
    return {"domain": DOMAIN, "nodes": nodes, "edges": [], "status": "partial", "note": "第一阶段仅返回目标节点，CVE/固件/镜像关系待后续 threat raw pipeline 补齐。"}


@router.post("/{item_id}/ai-review")
def ai_review(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """On-demand AI risk review for a single threat target.

    Reads the domain_item payload, calls LLM (or local_rules fallback),
    writes evidence, and returns the assessment JSON.
    If an existing risk_assessment evidence is found, returns cached result.
    """
    row = conn.execute(
        "SELECT * FROM domain_items WHERE id = ? AND domain = ?",
        (item_id, DOMAIN),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="target not found")
    target = repo.row_to_dict(row)

    # Check for cached AI review
    existing = conn.execute(
        "SELECT * FROM evidence_items WHERE domain_item_id = ? AND evidence_type = 'risk_assessment' ORDER BY id DESC LIMIT 1",
        (item_id,),
    ).fetchone()
    if existing:
        existing_data = repo.row_to_dict(existing)
        return {"item_id": item_id, "status": "cached", "assessment": existing_data.get("payload", {})}

    # Call LLM
    prompt = _semantic_review_prompt()
    review_payload = _semantic_review_payload(target)
    router = LLMRouter()
    output = router.complete_json(profile="configured_model", prompt=prompt, payload=review_payload)

    # Build assessment
    assessment = _build_assessment(target, output)

    # Persist to evidence_items
    score = float(target.get("score") or 0)
    repo.create_evidence(
        conn,
        domain=DOMAIN,
        domain_item_id=item_id,
        evidence_type="risk_assessment",
        title="AI 研判结果",
        content=assessment.get("summary", ""),
        source_url=target.get("source_url") or "",
        confidence=assessment.get("semantic_review", {}).get("confidence"),
        payload=assessment,
    )

    return {"item_id": item_id, "status": "success", "assessment": assessment}
