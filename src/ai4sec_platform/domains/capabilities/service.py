"""能力洞察 service 层 - 对齐 demo 4 份数据契约。

提供 today/library/repro_runs/conversions 的 service 函数，
被 app/api/capabilities.py 和 app/api/frontend.py 调用。
"""
from __future__ import annotations

import sqlite3

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.services import domain_items

DOMAIN = "capabilities"


# ============================================================================
# 已有（保留 + 扩展）
# ============================================================================
def today(conn: sqlite3.Connection, limit: int = 12) -> dict:
    """今日能力（对齐 demo today.json）"""
    return domain_items.today(conn, DOMAIN, limit=limit)


def list_items(conn: sqlite3.Connection, limit: int = 50) -> dict:
    """能力库（对齐 demo library.json）"""
    return domain_items.list_items(conn, DOMAIN, limit=limit)


def detail(conn: sqlite3.Connection, item_id: int) -> dict | None:
    """能力详情（对齐 demo capability_detail.sample.json）"""
    return domain_items.detail(conn, DOMAIN, item_id)


# ============================================================================
# 新增
# ============================================================================
def repro_runs(conn: sqlite3.Connection, *, item_id: int | None = None, limit: int = 50) -> dict:
    """复现任务列表（对齐 demo repro_runs.json）"""
    tasks = repo.list_repro_tasks(conn, item_id=item_id, limit=limit)
    return {
        "domain": DOMAIN,
        "items": [
            {
                "id": f"repro-{t['item_id']}",
                "capability_id": str(t["item_id"]),
                "title": (t.get("repo_url") or "").split("/")[-1] if t.get("repo_url") else "",
                "status": t["status"],
                "repo_url": t.get("repo_url", ""),
                "environment": "auto-runner",
                "last_event": (t.get("result") or "")[:100] if t.get("result") else "",
                "artifacts": [],
                "task_id": t["id"],
            }
            for t in tasks
        ],
    }


def conversions(conn: sqlite3.Connection, limit: int = 50) -> dict:
    """能力转化记录（对齐 demo conversions.json）"""
    items = repo.list_domain_items(conn, DOMAIN, item_type="capability_conversion", limit=limit)
    return {
        "domain": DOMAIN,
        "items": [
            {
                "id": f"conv-{it['id']}",
                "capability_id": str((it.get("payload") or {}).get("capability_id", "")),
                "title": it.get("title", ""),
                "status": (it.get("payload") or {}).get("status", "持续观察"),
                "scenario": (it.get("payload") or {}).get("scenario", ""),
                "owner": (it.get("payload") or {}).get("owner", ""),
                "next_action": (it.get("payload") or {}).get("next_action", ""),
                "notes": (it.get("payload") or {}).get("notes", ""),
            }
            for it in items
        ],
    }


def classify_stats(conn: sqlite3.Connection) -> dict:
    """Web 分类统计（迁自旧 db.py get_web_classify_stats）"""
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


def stats(conn: sqlite3.Connection) -> dict:
    """能力洞察总览统计"""
    all_items = repo.list_domain_items(conn, DOMAIN, limit=10000)
    items = all_items
    candidates = [it for it in items if it.get("item_type") == "capability_candidate"]
    capabilities = [it for it in items if it.get("item_type") == "capability"]
    conversions_list = [it for it in items if it.get("item_type") == "capability_conversion"]

    succeeded = repo.get_succeeded_repro_item_ids(conn)
    active = repo.get_active_repro_item_ids(conn)

    return {
        "total": len(items),
        "candidates": len(candidates),
        "capabilities": len(capabilities),
        "conversions": len(conversions_list),
        "repro_succeeded": len(succeeded),
        "repro_active": len(active),
    }
