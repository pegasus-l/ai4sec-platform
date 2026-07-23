from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db import repositories as repo

router = APIRouter(prefix="/ops", tags=["ops"])


def _table_count(conn: sqlite3.Connection, table: str) -> int:
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    except Exception:
        return 0


def _days_ago(iso_str: str) -> int | None:
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


@router.get("/overview")
def overview(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """System overview: DB stats, last pipeline run, AI analysis counts, source freshness."""
    # DB stats
    db_stats = {
        "repos": _table_count(conn, "domain_items") and conn.execute(
            "SELECT COUNT(*) FROM domain_items WHERE domain='threats' AND item_type='target'"
        ).fetchone()[0],
        "assets": conn.execute(
            "SELECT COUNT(*) FROM domain_items WHERE domain='threats' AND item_type='asset'"
        ).fetchone()[0],
        "today": conn.execute(
            "SELECT COUNT(*) FROM domain_items WHERE domain='threats' AND item_type='target' AND score >= 75"
        ).fetchone()[0],
        "queue": _table_count(conn, "human_queue_items"),
        "cve_unique": conn.execute(
            "SELECT COUNT(DISTINCT json_extract(payload_json, '$.cves[0].cve_id')) FROM domain_items WHERE domain='threats' AND item_type='target'"
        ).fetchone()[0] if _table_count(conn, "domain_items") else 0,
        "pipeline_runs": _table_count(conn, "pipeline_runs"),
        "evidence_items": _table_count(conn, "evidence_items"),
        "quality_audits": _table_count(conn, "quality_audits"),
    }

    # Last pipeline run
    last_run = None
    run_row = conn.execute(
        "SELECT run_id, pipeline_name, status, started_at, finished_at FROM pipeline_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if run_row:
        last_run = {
            "run_id": run_row[0],
            "pipeline": run_row[1],
            "status": run_row[2],
            "started_at": run_row[3],
            "finished_at": run_row[4],
            "days_ago": _days_ago(run_row[3] or ""),
        }

    # AI analysis counts
    ai_stats = {
        "ai_reviews": conn.execute(
            "SELECT COUNT(*) FROM evidence_items WHERE evidence_type='risk_assessment'"
        ).fetchone()[0],
        "asset_associations": conn.execute(
            "SELECT COUNT(*) FROM evidence_items WHERE evidence_type='asset_association'"
        ).fetchone()[0],
        "model_calls": _table_count(conn, "model_calls"),
    }

    # AI review items (repos with AI calibration)
    ai_review_items = []
    ai_rows = conn.execute(
        "SELECT domain_item_id, payload_json FROM evidence_items WHERE evidence_type='risk_assessment' ORDER BY id DESC LIMIT 20"
    ).fetchall()
    for row in ai_rows:
        item_id = row[0]
        import json
        payload = json.loads(row[1]) if row[1] else {}
        semantic = payload.get("semantic_review") or {}
        # Get repo title
        repo_row = conn.execute("SELECT title, score FROM domain_items WHERE id=?", (item_id,)).fetchone()
        ai_review_items.append({
            "item_id": item_id,
            "title": repo_row[0] if repo_row else "?",
            "score": repo_row[1] if repo_row else 0,
            "summary": semantic.get("summary", ""),
            "calibrated_surface": semantic.get("calibrated_surface", ""),
            "confidence": semantic.get("confidence", 0),
        })

    # Asset association items
    ai_assoc_items = []
    assoc_rows = conn.execute(
        "SELECT domain_item_id, payload_json FROM evidence_items WHERE evidence_type='asset_association' ORDER BY id DESC LIMIT 20"
    ).fetchall()
    for row in assoc_rows:
        item_id = row[0]
        import json
        payload = json.loads(row[1]) if row[1] else {}
        associations = payload.get("associations", [])
        asset_row = conn.execute("SELECT title, source FROM domain_items WHERE id=?", (item_id,)).fetchone()
        ai_assoc_items.append({
            "item_id": item_id,
            "title": asset_row[0] if asset_row else "?",
            "source": asset_row[1] if asset_row else "",
            "association_count": len(associations),
            "summary": payload.get("summary", ""),
            "associations": associations[:5],
        })

    return {
        "db_stats": db_stats,
        "last_run": last_run,
        "ai_stats": ai_stats,
        "ai_reviews": ai_review_items,
        "ai_associations": ai_assoc_items,
    }


@router.get("/sources")
def sources(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """Source health from raw_artifacts, grouped by source."""
    rows = conn.execute(
        "SELECT source, COUNT(*) as records, MAX(created_at) as last_sync, item_count "
        "FROM raw_artifacts WHERE domain='threats' GROUP BY source ORDER BY source"
    ).fetchall()
    items = []
    for r in rows:
        items.append({
            "source": r[0],
            "records": r[1],
            "last_sync": r[2],
            "days_ago": _days_ago(r[2] or ""),
            "total_items": r[3] or 0,
        })
    return {"items": items}


@router.get("/quality")
def quality(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """Quality audits from quality_audits table."""
    rows = conn.execute(
        "SELECT id, domain, audit_type, status, score, summary, details_json, created_at "
        "FROM quality_audits ORDER BY id DESC LIMIT 50"
    ).fetchall()
    items = []
    for r in rows:
        import json
        details = {}
        try:
            details = json.loads(r[6]) if r[6] else {}
        except Exception:
            details = {}
        items.append({
            "id": r[0],
            "domain": r[1],
            "audit_type": r[2],
            "status": r[3],
            "score": r[4],
            "summary": (r[5] or "")[:200],
            "details": details,
            "created_at": r[7],
        })
    total = len(items)
    passed = len([i for i in items if i["status"] == "pass"])
    warned = len([i for i in items if i["status"] in ("warn", "warning")])
    failed = len([i for i in items if i["status"] in ("fail", "failed")])
    return {"items": items, "kpis": {"total": total, "passed": passed, "warned": warned, "failed": failed}}


@router.get("/ai-summary")
def ai_summary(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """AI analysis summary: list of AI-reviewed repos + asset associations."""
    # AI reviewed repos
    review_items = []
    rows = conn.execute(
        "SELECT domain_item_id, payload_json FROM evidence_items WHERE evidence_type='risk_assessment' ORDER BY id DESC"
    ).fetchall()
    for row in rows:
        item_id = row[0]
        import json
        payload = json.loads(row[1]) if row[1] else {}
        semantic = payload.get("semantic_review") or {}
        repo_row = conn.execute("SELECT title, score, source_url FROM domain_items WHERE id=?", (item_id,)).fetchone()
        review_items.append({
            "item_id": item_id,
            "title": repo_row[0] if repo_row else "?",
            "score": repo_row[1] if repo_row else 0,
            "url": repo_row[2] if repo_row else "",
            "summary": semantic.get("summary", ""),
            "calibrated_surface": semantic.get("calibrated_surface", ""),
            "rule_score_assessment": semantic.get("rule_score_assessment", ""),
            "hypotheses": semantic.get("hypotheses", []),
            "confidence": semantic.get("confidence", 0),
            "cve_priority": semantic.get("cve_priority", []),
        })

    # Asset associations
    assoc_items = []
    rows = conn.execute(
        "SELECT domain_item_id, payload_json FROM evidence_items WHERE evidence_type='asset_association' ORDER BY id DESC"
    ).fetchall()
    for row in rows:
        item_id = row[0]
        import json
        payload = json.loads(row[1]) if row[1] else {}
        asset_row = conn.execute("SELECT title, source FROM domain_items WHERE id=?", (item_id,)).fetchone()
        assoc_items.append({
            "item_id": item_id,
            "title": asset_row[0] if asset_row else "?",
            "source": asset_row[1] if asset_row else "",
            "summary": payload.get("summary", ""),
            "associations": payload.get("associations", []),
            "reviewed_at": payload.get("reviewed_at", ""),
        })

    return {
        "ai_reviews": {"count": len(review_items), "items": review_items},
        "asset_associations": {"count": len(assoc_items), "items": assoc_items},
    }


@router.get("/pipelines")
def available_pipelines() -> dict:
    """List available pipelines for the tasks page."""
    from ai4sec_platform.pipelines.registry import default_registry
    registry = default_registry()
    all_pipes = registry.list()
    pipelines = []
    for item in all_pipes:
        name = item.get("name", "") if isinstance(item, dict) else str(item)
        if name.startswith("threats."):
            pipelines.append({
                "name": name,
                "short_name": name.replace("threats.", ""),
                "domain": item.get("domain", "") if isinstance(item, dict) else "",
                "steps": item.get("steps", "") if isinstance(item, dict) else "",
                "description": _pipeline_description(name),
                "risk": "高" if "full" in name else "中",
                "estimated_time": "30-60 min" if "full" in name else "5-15 min",
            })
    pipelines.sort(key=lambda p: p["name"])
    return {"items": pipelines}


def _pipeline_description(name: str) -> str:
    descs = {
        "threats.huawei_full_migration_pipeline": "从采集到报告全链路（采集+CVE侦察+攻击面+导入+评分+资产+风险推理+报告）",
        "threats.huawei_raw_pipeline": "快速刷新：导入 raw 数据 + 标准化 + 构建威胁条目 + 风险评分",
        "threats.huawei_cve_scout_pipeline": "CVE/SA 侦察：刷新 security repo pool 与项目匹配",
        "threats.huawei_attack_surface_pipeline": "攻击面评分：对 repos 做 5 维度攻击面打分",
        "threats.huawei_asset_pipeline": "资产同步：固件/AscendHub/mirrors/OpenX",
        "threats.huawei_collect_sources_pipeline": "采集源：采集 GitCode/mirrors/openx 等源数据",
        "threats.risk_reasoning_pipeline": "风险推理：选 Top N 候选 + LLM 语义复核",
    }
    return descs.get(name, "—" + name)
