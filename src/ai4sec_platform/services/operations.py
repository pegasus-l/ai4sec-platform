from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo

RULES = {
    "news": [
        {"name": "核心推荐阈值", "value": "score >= 8", "description": "高分资讯进入重点展示。"},
        {"name": "能力候选", "value": "has_code or repo", "description": "有代码实现的高价值条目进入能力洞察。"},
    ],
    "capabilities": [
        {"name": "复现状态", "value": "local_rules", "description": "基于本地规则判断待复现、待资料补齐和转化优先级。"},
    ],
    "threats": [
        {"name": "高风险目标", "value": "attack_surface_score >= 80", "description": "优先进入人工复核和跟踪队列。"},
    ],
    "vulnerabilities": [
        {"name": "知识提取候选", "value": "is_relevant && confidence >= 0.7", "description": "高相关素材进入知识提取人工队列。"},
    ],
}


def tasks(conn: sqlite3.Connection, domain: str | None = None) -> dict[str, Any]:
    return {"domain": domain or "all", "items": repo.list_table(conn, "pipeline_runs", domain=domain, limit=50)}


def sources(conn: sqlite3.Connection, domain: str | None = None) -> dict[str, Any]:
    return {"domain": domain or "all", "items": repo.list_table(conn, "data_sources", domain=domain, limit=50)}


def audits(conn: sqlite3.Connection, domain: str | None = None) -> dict[str, Any]:
    return {"domain": domain or "all", "items": repo.list_table(conn, "quality_audits", domain=domain, limit=50)}


def human_queue(conn: sqlite3.Connection, domain: str | None = None) -> dict[str, Any]:
    return {"domain": domain or "all", "items": repo.list_table(conn, "human_queue_items", domain=domain, limit=50)}


def rules(domain: str | None = None) -> dict[str, Any]:
    if domain:
        return {"domain": domain, "items": RULES.get(domain, [])}
    return {"domain": "all", "items": RULES}


def model_calls(conn: sqlite3.Connection, domain: str | None = None) -> list[dict[str, Any]]:
    return repo.list_table(conn, "model_calls", domain=None, limit=50)
