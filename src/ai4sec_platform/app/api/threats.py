from __future__ import annotations

import sqlite3
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

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
def today(limit: int = Query(30, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.today(conn, DOMAIN, limit=limit)


@router.get("/targets")
def targets(
    limit: int = Query(50, ge=1, le=200),
    page: int = Query(1, ge=1),
    fields: str = Query("summary", description="summary=lightweight, full=complete payload"),
    surface: str = Query("", description="filter by attack surface"),
    grade: str = Query("", description="filter by grade (A/B/C/D)"),
    search: str = Query("", description="search in title/org"),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    """Paginated targets with optional filtering. Returns lightweight summary by default."""
    offset = (page - 1) * limit

    # Build query with filters
    where_clauses = ["domain = ?", "item_type = ?"]
    params = [DOMAIN, "target"]
    if surface:
        where_clauses.append("EXISTS (SELECT 1 FROM threat_item_dimensions tid WHERE tid.domain_item_id = domain_items.id AND tid.attack_surface = ?)")
        params.append(surface)
    if grade:
        where_clauses.append("EXISTS (SELECT 1 FROM threat_item_dimensions tid WHERE tid.domain_item_id = domain_items.id AND tid.attack_surface_grade = ?)")
        params.append(grade)
    if search:
        where_clauses.append("(title LIKE ? OR source LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    where_sql = " AND ".join(where_clauses)

    # Get total count
    total = conn.execute(f"SELECT COUNT(*) FROM domain_items WHERE {where_sql}", params).fetchone()[0]

    # Get items
    rows = conn.execute(
        f"SELECT * FROM domain_items WHERE {where_sql} ORDER BY score DESC LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()
    items = [repo.row_to_dict(row) for row in rows]

    # Strip payload for summary mode (list view doesn't need full payload)
    if fields == "summary":
        for item in items:
            payload = item.pop("payload", {})
            if isinstance(payload, dict):
                signals = payload.get("vulnerability_signals") or payload.get("signals") or {}
                attack_surface = payload.get("attack_surface") or {}
                raw = payload.get("raw") or {}
                item["signals_summary"] = {
                    "cve_count": signals.get("cve_count") or payload.get("cve_count") or 0,
                    "sa_count": signals.get("sa_count") or payload.get("sa_count") or 0,
                    "broad_sec_count": signals.get("broad_sec_count") or payload.get("broad_sec_count") or 0,
                    "direct_cve_count": signals.get("direct_cve_count") if signals.get("direct_cve_count") is not None else payload.get("direct_cve_count", 0),
                    "coordination_cve_count": signals.get("coordination_cve_count") if signals.get("coordination_cve_count") is not None else payload.get("coordination_cve_count", 0),
                    "direct_sa_count": signals.get("direct_sa_count") if signals.get("direct_sa_count") is not None else payload.get("direct_sa_count", 0),
                    "coordination_sa_count": signals.get("coordination_sa_count") if signals.get("coordination_sa_count") is not None else payload.get("coordination_sa_count", 0),
                    "direct_broad_sec_count": signals.get("direct_broad_sec_count") if signals.get("direct_broad_sec_count") is not None else payload.get("direct_broad_sec_count", 0),
                    "coordination_broad_sec_count": signals.get("coordination_broad_sec_count") if signals.get("coordination_broad_sec_count") is not None else payload.get("coordination_broad_sec_count", 0),
                }
                coordination = payload.get("coordination_summary") or {}
                item["coordination_summary"] = {
                    "cve_count": coordination.get("cve_count") or sum(
                        1 for cve in payload.get("cves") or []
                        if isinstance(cve, dict) and cve.get("association_scope") == "organization_coordination"
                    ),
                    "target_projects": coordination.get("target_projects") or sorted({
                        str(cve.get("target_project")) for cve in payload.get("cves") or []
                        if isinstance(cve, dict) and cve.get("target_project")
                    }),
                }
                # AI calibration takes priority over rule-based surface
                ai_cal = payload.get("ai_calibration") or {}
                risk_assessment = payload.get("risk_assessment") or {}
                semantic = risk_assessment.get("semantic_review") or {}
                calibrated_surface = ai_cal.get("calibrated_surface") or semantic.get("calibrated_surface") or ""
                rule_surface = (attack_surface.get("signals") or {}).get("primary_attack_surface", "") \
                    if isinstance(attack_surface.get("signals"), dict) else attack_surface.get("primary_attack_surface", "")
                item["attack_surface_summary"] = {
                    "score": attack_surface.get("score", 0),
                    "grade": attack_surface.get("grade", ""),
                    "surface": calibrated_surface or rule_surface,
                }
                item["raw_name"] = raw.get("name", "")
                item["raw_org"] = raw.get("org", "")
                # Score breakdown + reasons (used by ScoreBreakdown component in list view)
                scoring = payload.get("scoring") or {}
                item["breakdown"] = scoring.get("breakdown") or attack_surface.get("breakdown") or {}
                item["reasons"] = scoring.get("reasons") or attack_surface.get("reasons") or []
                # Star count + total security items (used in list view)
                item["stars"] = payload.get("stars") or raw.get("star_count") or 0
                item["total_sec_items"] = payload.get("total_sec_items") or signals.get("total_sec_items") or 0
                # AI calibrated flag (badge in list view)
                item["aiCalibrated"] = bool(calibrated_surface or ai_cal.get("calibrated_attack_surface") or semantic.get("attack_surface_calibration"))

    return {"items": items, "total": total, "page": page, "per_page": limit, "pages": (total + limit - 1) // limit}


@router.get("/targets/{item_id}")
def target_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="target not found")
    return item


@router.get("/tracking-queue")
def tracking_queue(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """User-initiated tracking items only (queue_source='user')."""
    rows = conn.execute(
        """
        SELECT h.*, d.title as target_title, d.source_url as target_url, d.score as target_score,
               d.source as target_source, d.item_type as target_type
        FROM human_queue_items h
        LEFT JOIN domain_items d ON h.item_id = d.id
        WHERE h.domain=? AND (h.queue_source='user' OR (h.queue_source IS NULL AND h.queue_type LIKE 'user%'))
        ORDER BY h.id DESC
        """,
        (DOMAIN,),
    ).fetchall()
    items = []
    for row in rows:
        item = repo.row_to_dict(row)
        # Add target info from JOIN
        item["title"] = item.pop("target_title", "") or item.get("reason", "")
        item["url"] = item.pop("target_url", "")
        item["score"] = item.pop("target_score", 0)
        item["source"] = item.pop("target_source", "")
        item["type"] = item.pop("target_type", "")
        items.append(item)
    return {"items": items}


class TrackRequest(BaseModel):
    priority: str = "P1"
    reason: str = ""


@router.post("/targets/{item_id}/track")
def track_target(item_id: int, request: TrackRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """Add a target to the user's tracking queue."""
    item = conn.execute("SELECT title FROM domain_items WHERE id=? AND domain=?", (item_id, DOMAIN)).fetchone()
    if not item:
        raise HTTPException(status_code=404, detail="target not found")
    now = datetime.now().isoformat()
    conn.execute(
        "INSERT INTO human_queue_items (domain, item_id, queue_type, status, priority, reason, assignee, payload_json, created_at, updated_at, queue_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (DOMAIN, item_id, "user_track", "待研判", request.priority, request.reason, "", "{}", now, now, "user"),
    )
    conn.commit()
    return {"status": "tracked", "item_id": item_id, "title": item[0], "priority": request.priority, "reason": request.reason}


@router.post("/assets/{item_id}/track")
def track_asset(item_id: int, request: TrackRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """Add an asset to the user's tracking queue."""
    item = conn.execute("SELECT title FROM domain_items WHERE id=? AND domain=?", (item_id, DOMAIN)).fetchone()
    if not item:
        raise HTTPException(status_code=404, detail="asset not found")
    now = datetime.now().isoformat()
    conn.execute(
        "INSERT INTO human_queue_items (domain, item_id, queue_type, status, priority, reason, assignee, payload_json, created_at, updated_at, queue_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (DOMAIN, item_id, "user_track", "待研判", request.priority, request.reason, "", "{}", now, now, "user"),
    )
    conn.commit()
    return {"status": "tracked", "item_id": item_id, "title": item[0], "priority": request.priority, "reason": request.reason}


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
def assets(limit: int = Query(200, ge=1, le=500), conn: sqlite3.Connection = Depends(get_db)) -> dict:
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
def graph(
    target_limit: int = Query(100, ge=1, le=500),
    asset_limit: int = Query(100, ge=1, le=500),
    target_page: int = Query(1, ge=1),
    asset_page: int = Query(1, ge=1),
    surface: str = Query(""),
    grade: str = Query(""),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    targets_data = _bounded_graph_items(conn, item_type="target", limit=target_limit, page=target_page, surface=surface, grade=grade)
    assets_data = _bounded_graph_items(conn, item_type="asset", limit=asset_limit, page=asset_page)
    truncated = targets_data["truncated"] or assets_data["truncated"]
    return {
        "domain": DOMAIN,
        "targets": targets_data,
        "assets": assets_data,
        "status": "partial" if truncated else "complete",
        "filters": {"surface": surface, "grade": grade},
        "note": "图谱按风险分数返回有界数据；结果已截断。" if truncated else "图谱数据完整。",
    }


def _bounded_graph_items(conn, *, item_type: str, limit: int, page: int = 1, surface: str = "", grade: str = "") -> dict:
    where = ["di.domain = ?", "di.item_type = ?"]
    params: list[object] = [DOMAIN, item_type]
    if surface and item_type == "target":
        where.append("tid.attack_surface = ?")
        params.append(surface)
    if grade and item_type == "target":
        where.append("tid.attack_surface_grade = ?")
        params.append(grade)
    where_sql = " AND ".join(where)
    join_sql = " LEFT JOIN threat_item_dimensions tid ON tid.domain_item_id = di.id" if item_type == "target" else ""
    total = int(conn.execute(f"SELECT COUNT(*) FROM domain_items di{join_sql} WHERE {where_sql}", params).fetchone()[0])
    rows = conn.execute(
        f"SELECT di.* FROM domain_items di{join_sql} WHERE {where_sql} ORDER BY di.score DESC, di.id DESC LIMIT ? OFFSET ?",
        [*params, limit, (page - 1) * limit],
    ).fetchall()
    return {"items": [repo.row_to_dict(row) for row in rows], "total": total, "page": page, "pages": (total + limit - 1) // limit, "limit": limit, "truncated": total > limit}


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

    # Write ai_calibration into domain_items payload (merge, not overwrite)
    existing_payload = target.get("payload") or {}
    if isinstance(existing_payload, str):
        import json as _json
        existing_payload = _json.loads(existing_payload)
    semantic = assessment.get("semantic_review") or {}
    existing_payload["ai_calibration"] = {
        "calibrated_attack_surface": semantic.get("attack_surface_calibration", ""),
        "calibrated_surface": semantic.get("calibrated_surface", ""),
        "calibrated_score": semantic.get("calibrated_score"),
        "score_assessment": semantic.get("rule_score_assessment", ""),
        "hypotheses": semantic.get("hypotheses", []),
        "cve_priority": semantic.get("cve_priority", []),
        "false_positives": semantic.get("false_positives", []),
        "reviewed_at": datetime.now().isoformat(),
    }
    repo.update_domain_item(conn, item_id=item_id, payload=existing_payload)
    conn.commit()

    return {"item_id": item_id, "status": "success", "assessment": assessment}


@router.get("/{item_id}/ai-review")
def get_ai_review(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """Get cached AI review without triggering LLM. Returns 404 if not cached."""
    row = conn.execute(
        "SELECT * FROM evidence_items WHERE domain_item_id = ? AND evidence_type = 'risk_assessment' ORDER BY id DESC LIMIT 1",
        (item_id,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="no cached review")
    data = repo.row_to_dict(row)
    return {"item_id": item_id, "status": "cached", "assessment": data.get("payload", {})}


def _asset_association_prompt() -> str:
    return """
你是华为开源生态分析专家。我给你一个资产信息和一批候选代码仓库，请判断哪些仓库和这个资产有关联。

关联类型：
- direct: 资产直接包含或依赖该仓库的代码（如固件包里有该仓库的 .so 文件）
- inferred: 通过产品线/生态链路推断关联（如 Atlas 固件 → CANN 仓库，因为 CANN 是 Atlas 的软件栈）
- weak: 间接关联（如镜像站包含该仓库的软件包）

如果没有关联，返回空数组。

输出 JSON：
{
  "associations": [
    {"repo_id": "仓库ID", "repo_name": "org/name", "confidence": "direct|inferred|weak", "reason": "关联理由"}
  ],
  "summary": "一句话总结关联情况"
}
""".strip()


@router.post("/assets/{item_id}/ai-associate")
def ai_associate(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """On-demand AI asset-to-repo association analysis."""
    # Read the asset
    row = conn.execute(
        "SELECT * FROM domain_items WHERE id = ? AND domain = ? AND item_type = ?",
        (item_id, DOMAIN, "asset"),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="asset not found")
    target = repo.row_to_dict(row)

    # Check cache
    existing = conn.execute(
        "SELECT * FROM evidence_items WHERE domain_item_id = ? AND evidence_type = 'asset_association' ORDER BY id DESC LIMIT 1",
        (item_id,),
    ).fetchone()
    if existing:
        existing_data = repo.row_to_dict(existing)
        return {"item_id": item_id, "status": "cached", "associations": existing_data.get("payload", {})}

    # Build asset info
    payload = target.get("payload") or {}
    if isinstance(payload, str):
        import json as _json
        payload = _json.loads(payload)
    raw = payload.get("raw") or {}
    asset_name = target.get("title", "")
    asset_source = payload.get("source", "")
    asset_desc = raw.get("msg") or raw.get("description") or raw.get("softwareExplain") or ""
    asset_model = raw.get("modelName") or raw.get("displayName") or raw.get("name") or raw.get("repoName") or ""

    # Pre-filter candidate repos by name matching (limit to top 30)
    all_repos = conn.execute(
        "SELECT id, title, source, summary, payload_json FROM domain_items WHERE domain = ? AND item_type = ? LIMIT 800",
        (DOMAIN, "target"),
    ).fetchall()

    candidates = []
    asset_words = set()
    for word in (asset_name + " " + asset_model + " " + asset_desc).lower().replace("/", " ").replace("-", " ").replace("_", " ").split():
        if len(word) >= 3:
            asset_words.add(word)

    for repo_row in all_repos:
        repo_data = repo.row_to_dict(repo_row)
        repo_title = repo_data.get("title", "")
        repo_summary = repo_data.get("summary", "")
        repo_text = (repo_title + " " + repo_summary).lower()
        # Match if any asset word appears in repo text
        if any(word in repo_text for word in asset_words):
            candidates.append({
                "repo_id": str(repo_data.get("id", "")),
                "repo_name": repo_title,
                "repo_summary": (repo_summary or "")[:100],
            })
        if len(candidates) >= 30:
            break

    # If no candidates from name matching, take top repos by score as fallback
    if not candidates:
        top_repos = conn.execute(
            "SELECT id, title, summary FROM domain_items WHERE domain = ? AND item_type = ? ORDER BY score DESC LIMIT 10",
            (DOMAIN, "target"),
        ).fetchall()
        for repo_row in top_repos:
            repo_data = repo.row_to_dict(repo_row)
            candidates.append({
                "repo_id": str(repo_data.get("id", "")),
                "repo_name": repo_data.get("title", ""),
                "repo_summary": (repo_data.get("summary") or "")[:100],
            })

    # Call LLM
    llm_payload = {
        "asset_name": asset_name,
        "asset_type": asset_source,
        "asset_model": asset_model,
        "asset_description": asset_desc[:300],
        "candidate_repos": candidates,
    }

    router_instance = LLMRouter()
    prompt = _asset_association_prompt()
    output = router_instance.complete_json(profile="configured_model", prompt=prompt, payload=llm_payload)

    # Normalize result
    result = output if isinstance(output, dict) else {}
    associations = result.get("associations") or result.get("result", {}).get("associations", [])
    summary = result.get("summary") or result.get("result", {}).get("summary", "已完成关联分析。")

    association_data = {"associations": associations, "summary": summary, "reviewed_at": datetime.now().isoformat()}

    # Cache to evidence
    repo.create_evidence(
        conn,
        domain=DOMAIN,
        domain_item_id=item_id,
        evidence_type="asset_association",
        title="AI 资产关联分析",
        content=summary,
        source_url=target.get("source_url") or "",
        confidence=None,
        payload=association_data,
    )

    # Write to domain_items payload
    if isinstance(payload, str):
        import json as _json
        payload = _json.loads(payload)
    payload["ai_association"] = association_data
    repo.update_domain_item(conn, item_id=item_id, payload=payload)
    conn.commit()

    return {"item_id": item_id, "status": "success", "associations": association_data}


@router.get("/assets/{item_id}/ai-associate")
def get_ai_associate(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """Get cached asset association without triggering LLM. Returns 404 if not cached."""
    row = conn.execute(
        "SELECT * FROM evidence_items WHERE domain_item_id = ? AND evidence_type = 'asset_association' ORDER BY id DESC LIMIT 1",
        (item_id,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="no cached association")
    data = repo.row_to_dict(row)
    return {"item_id": item_id, "status": "cached", "associations": data.get("payload", {})}


@router.get("/surface-stats")
def surface_stats(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """Aggregate stats per attack surface — used by attack-surface view KPIs.

    Returns total_repos, total_cves, total_sec, and per_surface breakdown.
    Queries payload_json via json_extract — one pass over domain_items.
    """
    rows = conn.execute(
        """
        SELECT
            COALESCE(NULLIF(tid.attack_surface, ''), 'unknown') AS surface,
            COUNT(*) AS count,
            COALESCE(SUM(tid.cve_count), 0) AS cves,
            COALESCE(SUM(tid.total_sec_count), 0) AS sec
        FROM domain_items di
        LEFT JOIN threat_item_dimensions tid ON tid.domain_item_id = di.id
        WHERE di.domain = ? AND di.item_type = 'target'
        GROUP BY surface
        """,
        (DOMAIN,),
    ).fetchall()

    per_surface = {}
    total_repos = 0
    total_cves = 0
    total_sec = 0
    for row in rows:
        surface = row[0] or "unknown"
        count = row[1] or 0
        cves = row[2] or 0
        sec = row[3] or 0
        per_surface[surface] = {"count": count, "cves": cves, "sec": sec}
        total_repos += count
        total_cves += cves
        total_sec += sec

    return {
        "total_repos": total_repos,
        "total_cves": total_cves,
        "total_sec": total_sec,
        "per_surface": per_surface,
    }
