"""T1.5 的展示层:候选列表(带优先级)与统计。

为什么单独一层:候选表有 1248 行、payload 在 `domain_items` 里动辄几十 KB,**列表只取标题与
URL 两列**,不能 `SELECT *`;分页与排序都在 SQL 里做(按 P0→P1→P2→未排序)。

排序口径(§4·5):档内按 CVSS、公开时间在查询层做——CVSS/时间在评分表与素材元数据里,
这里只保证**档位顺序**正确,档内按素材 id 倒序(新素材在前)。
"""

from __future__ import annotations

import sqlite3
from typing import Any

PRIORITIES: tuple[str, ...] = ("P0", "P1", "P2")
_ORDER = "CASE c.priority WHEN 'P0' THEN 0 WHEN 'P1' THEN 1 WHEN 'P2' THEN 2 ELSE 3 END"


def _where(*, priority: str | None, screenable: bool | None, q: str | None,
           has_task: bool | None) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if priority:
        if priority not in PRIORITIES:
            raise ValueError(f"未知优先级 {priority!r}; 可选: {', '.join(PRIORITIES)}")
        clauses.append("c.priority = ?")
        params.append(priority)
    if screenable is not None:
        clauses.append("c.screenable = ?")
        params.append(1 if screenable else 0)
    if q:
        clauses.append("(d.title LIKE ? OR c.target_repo LIKE ? OR c.target_cve LIKE ?)")
        params.extend([f"%{q}%"] * 3)
    if has_task is not None:
        clauses.append(("EXISTS" if has_task else "NOT EXISTS")
                       + " (SELECT 1 FROM writeup_repro_tasks t WHERE t.material_id = c.material_id)")
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def list_candidates(
    conn: sqlite3.Connection,
    *,
    priority: str | None = None,
    screenable: bool | None = True,
    q: str | None = None,
    has_task: bool | None = None,
    limit: int = 30,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    clause, params = _where(priority=priority, screenable=screenable, q=q, has_task=has_task)
    total = conn.execute(
        "SELECT COUNT(*) FROM writeup_repro_candidates c"
        " LEFT JOIN domain_items d ON d.id = c.material_id" + clause, params,
    ).fetchone()[0]
    rows = conn.execute(
        "SELECT c.material_id, c.screenable, c.reject_reason, c.priority, c.priority_reason,"
        "       c.asset_hit, c.asset_ids, c.asset_confidence, c.has_poc, c.poc_lang,"
        "       c.target_kind, c.target_repo, c.target_version, c.target_cve, c.target_product,"
        "       c.claimed_effect, d.title, d.source_url,"
        "       (SELECT t.id FROM writeup_repro_tasks t WHERE t.material_id = c.material_id"
        "         ORDER BY t.id DESC LIMIT 1) AS task_id,"
        "       (SELECT t.status FROM writeup_repro_tasks t WHERE t.material_id = c.material_id"
        "         ORDER BY t.id DESC LIMIT 1) AS task_status,"
        "       (SELECT t.verdict FROM writeup_repro_tasks t WHERE t.material_id = c.material_id"
        "         ORDER BY t.id DESC LIMIT 1) AS task_verdict"
        "  FROM writeup_repro_candidates c"
        "  LEFT JOIN domain_items d ON d.id = c.material_id" + clause +
        f" ORDER BY {_ORDER}, c.material_id DESC LIMIT ? OFFSET ?",
        [*params, int(limit), int(offset)],
    ).fetchall()
    return [dict(row) for row in rows], int(total)


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """按优先级统计(只算可复现的),外加"已建任务"数 —— 页面顶部那排筛选芯片用它。"""
    by_priority = {row[0] or "": int(row[1]) for row in conn.execute(
        "SELECT priority, COUNT(*) FROM writeup_repro_candidates"
        " WHERE screenable = 1 GROUP BY priority")}
    return {
        "screenable": sum(by_priority.values()),
        "by_priority": {p: by_priority.get(p, 0) for p in PRIORITIES},
        "with_task": conn.execute(
            "SELECT COUNT(DISTINCT c.material_id) FROM writeup_repro_candidates c"
            " WHERE c.screenable = 1 AND EXISTS (SELECT 1 FROM writeup_repro_tasks t"
            "   WHERE t.material_id = c.material_id)").fetchone()[0],
    }
