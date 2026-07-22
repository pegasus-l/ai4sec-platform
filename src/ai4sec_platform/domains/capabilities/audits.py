"""能力洞察审计 - 复现失败审计 + 能力卡缺字段审计 + Web 分类统计。

迁自旧 v1 db.py get_web_classify_stats + 扩展。
"""
from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo

DOMAIN = "capabilities"


def audit_capability_items(items: list[dict]) -> dict:
    """保留现有接口 + 扩展：审计能力卡缺字段"""
    missing_source_url = sum(1 for it in items if not it.get("source_url"))
    missing_code_url = sum(1 for it in items if not (it.get("payload") or {}).get("code_url"))
    missing_score = sum(1 for it in items if it.get("score") is None)
    missing_capability_type = sum(
        1 for it in items
        if not (it.get("payload") or {}).get("capability_type")
        and it.get("item_type") == "capability"
    )
    return {
        "count": len(items),
        "missing_source_url": missing_source_url,
        "missing_code_url": missing_code_url,
        "missing_score": missing_score,
        "missing_capability_type": missing_capability_type,
    }


def audit_repro_failures(conn: sqlite3.Connection, *, limit: int = 50) -> dict:
    """审计复现失败任务（迁自旧 v1 的失败任务检测）"""
    tasks = repo.list_repro_tasks(conn, limit=limit * 3, include_cleaned=True)
    failed = [t for t in tasks if t["status"] in ("failed", "timeout", "stopped")]
    by_status: dict[str, int] = {}
    by_reason: list[dict[str, Any]] = []
    for t in failed:
        status = t["status"]
        by_status[status] = by_status.get(status, 0) + 1
        result = (t.get("result") or "")[:200]
        by_reason.append({
            "task_id": t["id"],
            "item_id": t["item_id"],
            "status": status,
            "reason": result,
        })
    return {
        "total_failed": len(failed),
        "by_status": by_status,
        "details": by_reason[:limit],
    }


def audit_missing_fields(conn: sqlite3.Connection, *, limit: int = 100) -> dict:
    """审计能力卡缺字段（对齐 demo today.json 字段完整性）"""
    items = repo.list_domain_items(conn, DOMAIN, item_type="capability", limit=limit)
    caps = items

    missing: dict[str, list[dict[str, Any]]] = {
        "capability_type": [],
        "sub_type": [],
        "application_scenarios": [],
        "implementation_depth": [],
        "repro_status": [],
        "conversion_status": [],
    }

    for cap in caps:
        payload = cap.get("payload") or {}
        item_info = {"id": cap["id"], "title": cap.get("title", "")[:50]}

        if not payload.get("capability_type"):
            missing["capability_type"].append(item_info)
        if not payload.get("sub_type"):
            missing["sub_type"].append(item_info)
        if not payload.get("application_scenarios"):
            missing["application_scenarios"].append(item_info)
        if not payload.get("implementation_depth"):
            missing["implementation_depth"].append(item_info)
        if not payload.get("repro_status"):
            missing["repro_status"].append(item_info)
        if not payload.get("conversion_status"):
            missing["conversion_status"].append(item_info)

    return {
        "total_audited": len(caps),
        "missing_counts": {k: len(v) for k, v in missing.items()},
        "details": missing,
    }


def get_web_classify_stats(conn: sqlite3.Connection) -> dict:
    """Web 分类统计（迁自旧 v1 db.py get_web_classify_stats）"""
    items = repo.list_domain_items(conn, DOMAIN, item_type="capability", limit=10000)
    all_items = items
    repo_filter = [
        it for it in all_items
        if (it.get("payload") or {}).get("code_url") or "github.com" in (it.get("source_url") or "")
    ]
    classified = [
        it for it in repo_filter
        if (it.get("payload") or {}).get("web_classify_ts")
    ]
    web_count = sum(1 for it in repo_filter if (it.get("payload") or {}).get("is_web"))
    return {
        "total": len(repo_filter),
        "classified": len(classified),
        "unclassified": len(repo_filter) - len(classified),
        "web_count": web_count,
    }


def run_full_audit(conn: sqlite3.Connection) -> dict:
    """运行完整审计（供 quality_audits 表记录）"""
    items = repo.list_domain_items(conn, DOMAIN, limit=10000)
    cap_items = [it for it in items if it.get("item_type") == "capability"]
    return {
        "capability_items": audit_capability_items(cap_items),
        "repro_failures": audit_repro_failures(conn),
        "missing_fields": audit_missing_fields(conn),
        "web_classify_stats": get_web_classify_stats(conn),
    }
