from __future__ import annotations

import sqlite3
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.domains.threats import linkage as threat_linkage
from ai4sec_platform.domains.threats import repo_filter
from ai4sec_platform.domains.threats import service as threat_service
from ai4sec_platform.services import domain_items
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
    limit: int = Query(50, ge=1, le=99999),
    page: int = Query(1, ge=1),
    fields: str = Query("summary", description="summary=lightweight, full=complete payload"),
    surface: str = Query("", description="filter by attack surface"),
    grade: str = Query("", description="filter by grade (A/B/C/D)"),
    search: str = Query("", description="search in title/org"),
    include_filtered: bool = Query(False, description="true=连同被规则判为无效的仓一起返回(前端「显示已过滤」开关)"),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    """Paginated targets with optional filtering. Returns lightweight summary by default.

    默认隐藏被 repo_filter 判为无效的仓(空壳/样例/镜像/文档…),并在 filtered_hidden 里给出
    隐藏条数;include_filtered=true 时全量返回,每行带 filtered / filtered_reason / filtered_code。
    判定表还没有数据时整个过滤逻辑自动退化为原行为(等价于 include_filtered=true)。
    """
    offset = (page - 1) * limit
    filtering = repo_filter.table_ready(conn)

    # Build query with filters(加了 JOIN 之后所有列名都要带 d. 前缀,否则列名歧义)
    where_clauses = ["d.domain = ?", "d.item_type = ?"]
    params = [DOMAIN, "target"]
    if surface:
        where_clauses.append("json_extract(d.payload_json, '$.attack_surface.signals.primary_attack_surface') = ?")
        params.append(surface)
    if grade:
        where_clauses.append("json_extract(d.payload_json, '$.attack_surface.grade') = ?")
        params.append(grade)
    if search:
        where_clauses.append("(d.title LIKE ? OR d.source LIKE ?)")
        params.extend([f"%{search}%", f"%{search}%"])
    where_sql = " AND ".join(where_clauses)

    join_sql, join_params, visible_sql, hidden_sql = "", [], "", ""
    if filtering:
        # 判定表为空时 f.filtered 恒为 NULL → COALESCE 成 0 → 一行都不会被隐藏
        join_sql = " LEFT JOIN threat_repo_filters f ON f.item_id = d.id AND f.domain = ?"
        join_params = [DOMAIN]
        visible_sql = " AND COALESCE(f.filtered, 0) = 0"
        hidden_sql = " AND COALESCE(f.filtered, 0) = 1"
    where_filtered = where_sql + ("" if include_filtered else visible_sql)

    # Get total count(隐藏条数与可见条数分别统计,前端要显示"已隐藏 N 个")
    base_from = f"FROM domain_items d{join_sql}"
    base_params = [*join_params, *params]
    total = conn.execute(f"SELECT COUNT(*) {base_from} WHERE {where_filtered}", base_params).fetchone()[0]
    filtered_hidden = 0
    if filtering:
        filtered_hidden = conn.execute(
            f"SELECT COUNT(*) {base_from} WHERE {where_sql}{hidden_sql}", base_params
        ).fetchone()[0]

    # Get items
    rows = conn.execute(
        f"SELECT d.* {base_from} WHERE {where_filtered} ORDER BY d.score DESC LIMIT ? OFFSET ?",
        [*base_params, limit, offset],
    ).fetchall()
    items = [repo.row_to_dict(row) for row in rows]

    # Attach per-row filter verdict
    verdicts = repo_filter.load_verdicts(conn, [item["id"] for item in items]) if filtering else {}
    for item in items:
        verdict = verdicts.get(item["id"]) or {}
        item["filtered"] = bool(verdict.get("filtered"))
        item["filtered_code"] = verdict.get("code") or ""
        item["filtered_reason"] = verdict.get("reason") or ""
        item["filtered_soft"] = bool(verdict.get("soft"))

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
                item["breakdown"] = attack_surface.get("breakdown") or scoring.get("breakdown") or {}
                item["reasons"] = scoring.get("reasons") or attack_surface.get("reasons") or []
                # Star count + total security items (used in list view)
                item["stars"] = payload.get("stars") or raw.get("star_count") or 0
                item["total_sec_items"] = payload.get("total_sec_items") or signals.get("total_sec_items") or 0
                # AI calibrated flag (badge in list view)
                item["aiCalibrated"] = bool(calibrated_surface or ai_cal.get("calibrated_attack_surface") or semantic.get("attack_surface_calibration"))

    return {
        "items": items,
        "total": total,
        "page": page,
        "per_page": limit,
        "pages": (total + limit - 1) // limit,
        # 被规则隐藏的仓数(只统计当前 surface/grade/search 口径下的);include_filtered=true 时为 0
        "filtered_hidden": filtered_hidden,
        "filtering_active": filtering,
    }


@router.get("/targets/{item_id}")
def target_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="target not found")
    # 详情页也可能从「已被过滤」的入口进来(抽屉/深链),所以这里同样把判定带上
    verdict = repo_filter.load_verdicts(conn, [item_id]).get(item_id) if repo_filter.table_ready(conn) else None
    item["filtered"] = bool((verdict or {}).get("filtered"))
    item["filtered_code"] = (verdict or {}).get("code") or ""
    item["filtered_reason"] = (verdict or {}).get("reason") or ""
    item["filtered_soft"] = bool((verdict or {}).get("soft"))
    return item


# 2026-10-08 领导反馈 #1/#3:跟踪队列与质量审计两个页面已下线,
# 相应的写接口(POST /targets/{id}/track、POST /assets/{id}/track)与只读接口
# (GET /tracking-queue、GET /audits、GET /tracking)一并移除,不留半开的写入口。
# 前端入口(加入跟踪按钮、侧边栏)已同步删除。


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
def assets(limit: int = Query(9999, ge=1, le=99999), conn: sqlite3.Connection = Depends(get_db)) -> dict:
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


def _split_org_name(title: str) -> tuple[str, str]:
    """repo title 'org/name' → (org, name);无 '/' 则 org 为空。"""
    title = title or ""
    if "/" in title:
        org, _, name = title.partition("/")
        return org, name
    return "", title


def _asset_category(asset_payload: dict) -> str:
    """资产品类:raw.category(list/str) 优先,否则退回 payload source/source_type。"""
    raw = asset_payload.get("raw") or {}
    cat = raw.get("category") or raw.get("subcategory") or ""
    if isinstance(cat, list):
        cat = ", ".join(str(c) for c in cat)
    if cat:
        return str(cat)
    return str(asset_payload.get("source_type") or asset_payload.get("source") or "")


def _repo_url(link: dict) -> str:
    """仓库主页 URL。优先取 domain_items.source_url(2026-10-08 起 list_threat_links 已带出),
    退回 payload 里的 url/html_url,再退回按组织名拼 gitcode —— 关联抽屉要给得出链接(R2)。"""
    direct = link.get("repo_source_url")
    if direct:
        return str(direct)
    rp = link.get("repo_payload") or {}
    raw = rp.get("raw") if isinstance(rp.get("raw"), dict) else {}
    for value in (rp.get("source_url"), rp.get("url"), raw.get("url"), raw.get("html_url"), raw.get("web_url")):
        if value:
            return str(value)
    org = (rp.get("org") if isinstance(rp.get("org"), str) else "") or raw.get("org") or ""
    name = (rp.get("name") if isinstance(rp.get("name"), str) else "") or raw.get("name") or ""
    if org and name:
        return f"https://gitcode.com/{org}/{name}"
    return ""


def _repo_meta(link: dict) -> dict:
    rp = link.get("repo_payload") or {}
    attack = rp.get("attack_surface") or {}
    signals = rp.get("vulnerability_signals") or rp.get("signals") or {}
    grade = attack.get("grade") if isinstance(attack, dict) else ""
    cve = signals.get("cve_count") if isinstance(signals, dict) else None
    if cve is None:
        cve = rp.get("cve_count")
    try:
        cve = int(cve or 0)
    except (TypeError, ValueError):
        cve = 0
    org, name = _split_org_name(link.get("repo_title") or "")
    return {
        "id": link["repo_id"],
        "org": org,
        "name": name or (link.get("repo_title") or ""),
        "grade": grade or "",
        "cve": cve,
        "risk": link.get("repo_score"),
        "url": _repo_url(link),
    }


def _asset_meta(link: dict, risk_in: float) -> dict:
    ap = link.get("asset_payload") or {}
    return {
        "id": link["asset_id"],
        "title": link.get("asset_title") or "",
        "source": link.get("asset_source") or "",
        "cat": _asset_category(ap),
        "risk_in": round(risk_in, 1),
    }


@router.get("/associations")
def associations(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """一次取回可渲染全集的关联 bundle:links + 三态资产 + meta。

    MVP 数据量小(167 资产量级)不做分页,前端客户端过滤/排序;not_run 全量返回有兜底上限。
    risk_in = 该资产入边仓库风险(score)之和,仅计 direct/inferred(弱关联是"无直接代码关联"的
    hedge,计入会把镜像站类扇出资产虚高顶到汇报榜;weak 边仍随 links 返回供 C 泳道复核/计数)。
    """
    links = repo.list_threat_links(conn, domain=DOMAIN)
    asset_rows = conn.execute(
        "SELECT id, title, source, payload_json FROM domain_items WHERE domain = ? AND item_type = 'asset' ORDER BY id",
        (DOMAIN,),
    ).fetchall()

    # risk_in 只累加 direct/inferred(弱关联 hedge 不计入风险数字)
    risk_in: dict[int, float] = {}
    for link in links:
        if (link.get("confidence") or "inferred") == "weak":
            continue
        asset_id = link["asset_id"]
        risk = link.get("repo_score")
        try:
            risk_in[asset_id] = risk_in.get(asset_id, 0.0) + (float(risk) if risk is not None else 0.0)
        except (TypeError, ValueError):
            pass

    edges_asset_ids: set[int] = {int(link["asset_id"]) for link in links}

    linked_ids: set[int] = set()
    orphan_rows: list[dict] = []
    not_run_rows: list[dict] = []
    for row in asset_rows:
        p = repo.loads(row["payload_json"], {})
        if not isinstance(p, dict):
            p = {}
        status = p.get("assoc_status")
        if status is None and p.get("ai_association"):
            aa = p.get("ai_association") or {}
            status = "linked" if aa.get("associations") else "orphan"
        entry = {"id": row["id"], "title": row["title"], "cat": _asset_category(p)}
        if row["id"] in edges_asset_ids:
            # 以边为准:有 threat_links 边才算真 linked(陈旧 linked 但无边的并入 not_run,与批跑口径一致)
            linked_ids.add(row["id"])
        elif status == "orphan":
            orphan_rows.append(entry)
        else:
            not_run_rows.append(entry)

    by_confidence = {"direct": 0, "inferred": 0, "weak": 0}
    serialized: list[dict] = []
    for link in links:
        conf = link.get("confidence") or "inferred"
        if conf in by_confidence:
            by_confidence[conf] += 1
        asset_id = link["asset_id"]
        serialized.append({
            "id": link["link_id"],
            "conf": conf,
            "rel_type": link.get("rel_type") or "related",
            "method": link.get("method") or "llm",
            "reason": link.get("reason") or "",
            "repo": _repo_meta(link),
            "asset": _asset_meta(link, risk_in.get(asset_id, 0.0)),
        })

    return {
        "meta": {
            "total_assets": len(asset_rows),
            "linked_assets": len(linked_ids),
            "orphan_assets": len(orphan_rows),
            "not_run_assets": len(not_run_rows),
            "total_links": len(serialized),
            "by_confidence": by_confidence,
        },
        "links": serialized,
        "orphans": orphan_rows,
        "not_run": not_run_rows[:300],
    }


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


@router.post("/assets/{item_id}/ai-associate")
def ai_associate(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """On-demand AI asset-to-repo association analysis(逻辑已抽到 domains/threats/linkage.py)。"""
    result = threat_linkage.run_asset_association(conn, asset_id=item_id)
    if result.get("status") == "error":
        raise HTTPException(status_code=404, detail=result.get("error", "asset not found"))
    return result


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
            COALESCE(
                json_extract(payload_json, '$.attack_surface.signals.primary_attack_surface'),
                json_extract(payload_json, '$.attack_surface.primary_attack_surface'),
                'unknown'
            ) as surface,
            COUNT(*) as count,
            COALESCE(SUM(
                COALESCE(json_extract(payload_json, '$.vulnerability_signals.cve_count'), 0)
            ), 0) as cves,
            COALESCE(SUM(
                COALESCE(json_extract(payload_json, '$.vulnerability_signals.broad_sec_count'), 0)
            ), 0) as sec
        FROM domain_items
        WHERE domain = ? AND item_type = 'target'
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
