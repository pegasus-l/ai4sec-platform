"""存量 event → 案例库的一次性迁移(可重复跑,幂等)。

背景:「漏洞事件库」原来是**从素材聚合出来的主题**(`item_type='event'`),存量 524 条里
单 CVE 139 / 多 CVE 152 / **无 CVE 的知识主题 233**。2026-10-16 领导要求它变成"一个个单独的洞",
所以旧 event 直接替掉,**但继承它们的素材关联** —— 否则新库上线当天是个空壳。

三步(**顺序不能换**):

1. `seed_cases_from_events()` —— 遍历非 superseded 的 event,把 `payload.cve_ids` 里每个 CVE
   建成一条案例(`status='pending_fetch'`、`source='legacy_event'`),并把该 event 的
   `payload.material_ids` 写成 `context_type='reference'`、`provenance='from_legacy_event'` 的
   上下文行(指向站内素材,抽屉里可直接跳)。**无 CVE 的 233 条不进**(领导要的是洞,不是主题)。
2. `supersede_legacy_events()` —— `status='superseded'`,**不删行**。`_active_events()`
   (domains/vulnerabilities/service.py)本来就过滤这个状态,所以事件列表自然清空;
   回滚只需要把 status 改回 active。
3. (人工)从 `pipelines/registry.py` 摘掉 event 聚合流水线的注册 —— 见该文件的注释。

必须在 supersede **之前**跑 seed:supersede 之后第 1 步就再也看不到那些 event 了。
两件事都幂等,重复跑只会有 0 新增。

跑法(容器内,PYTHONPATH 必须指到 src):

    docker exec -e PYTHONPATH=/app/src fusion-v2-ai4sec-1 python3 -m ai4sec_platform.domains.vulnerabilities.legacy_event_migration --seed --supersede

先看数就加 `--dry-run`(只统计不写)。注意这个模块**自己开库**(走 db.session.connect,
带 WAL + foreign_keys ON),不要在 API 进程里 import 它的入口函数。
"""

from __future__ import annotations

import sys
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.vulnerabilities import cases as cases_repo

DOMAIN = "vulnerabilities"
# 这些 event 没有 CVE,是"知识主题",不是洞 —— 按拍板不进案例库
TOPIC_KINDS = {"knowledge_topic"}


def seed_cases_from_events(conn, *, dry_run: bool = False, actor: str = "legacy_event_migration") -> dict[str, Any]:
    """把旧 event 里的 CVE 与素材关联搬进案例库。返回统计。"""
    rows = conn.execute(
        "SELECT id, title, summary, payload_json FROM domain_items WHERE domain = ? AND item_type = 'event' AND status != 'superseded' ORDER BY id",
        (DOMAIN,),
    ).fetchall()
    stats: dict[str, Any] = {
        "events_scanned": len(rows),
        "events_with_cve": 0,
        "events_skipped_no_cve": 0,
        "cases_created": 0,
        "cases_updated": 0,
        "context_inserted": 0,
        "distinct_cves": 0,
        "skipped_kinds": {},
    }
    cves: set[str] = set()
    for row in rows:
        payload = repo.loads(row["payload_json"], {}) or {}
        kind = str(payload.get("kind") or "")
        cve_ids = [str(value).strip().upper() for value in payload.get("cve_ids") or [] if str(value).strip()]
        material_ids = [int(value) for value in payload.get("material_ids") or []]
        if not cve_ids:
            stats["events_skipped_no_cve"] += 1
            stats["skipped_kinds"][kind or "unknown"] = stats["skipped_kinds"].get(kind or "unknown", 0) + 1
            continue
        stats["events_with_cve"] += 1
        materials = _material_meta(conn, material_ids)
        context_rows = [
            {
                "context_type": "reference",
                "provenance": "from_legacy_event",
                # 不给 content:素材正文不进上下文表(会重演威胁域 800MB 的坑),
                # 抽屉按 ref_item_id 去读原素材。空 content + ref_item_id 时指纹取自素材 id,
                # 所以同一条素材重复挂到同一个洞上只会落一行。
                "content": "",
                "ref_item_id": material_id,
                "label": materials.get(material_id, {}).get("title") or f"素材 #{material_id}",
                "source_url": materials.get(material_id, {}).get("source_url") or "",
            }
            for material_id in material_ids
        ]
        for cve_id in dict.fromkeys(cve_ids):
            cves.add(cve_id)
            if dry_run:
                stats["cases_created"] += 1
                stats["context_inserted"] += len(context_rows)
                continue
            result = cases_repo.upsert_case(
                conn,
                canonical_id=cve_id,
                id_kind="cve",
                title=str(row["title"] or cve_id),
                summary=str(payload.get("root_cause_summary") or row["summary"] or ""),
                cwe_ids=[str(value) for value in payload.get("cwe_ids") or []],
                source="legacy_event",
                status="pending_fetch",
                actor=actor,
                context_rows=context_rows,
                legacy_material_ids=material_ids,
                payload={"seeded_from_event": int(row["id"]), "seeded_at": utc_now(), "legacy_kind": kind},
            )
            stats["cases_created" if result["created"] else "cases_updated"] += 1
            stats["context_inserted"] += int(result.get("context_inserted") or 0)
    stats["distinct_cves"] = len(cves)
    return stats


def supersede_legacy_events(conn, *, dry_run: bool = False) -> int:
    """旧 event 全部置 superseded(**不删行**)。回滚 = 把这批改回 active。"""
    count = int(conn.execute("SELECT COUNT(*) FROM domain_items WHERE domain = ? AND item_type = 'event' AND status != 'superseded'", (DOMAIN,)).fetchone()[0])
    if not count or dry_run:
        return count
    conn.execute(
        "UPDATE domain_items SET status = 'superseded' WHERE domain = ? AND item_type = 'event' AND status != 'superseded'",
        (DOMAIN,),
    )
    conn.commit()
    return count


def recompute_all(conn) -> int:
    """批量重算所有案例的 4 位上下文完整度(改了口径/补了历史数据后用)。"""
    case_ids = [int(row["id"]) for row in conn.execute("SELECT id FROM vulnerability_cases ORDER BY id").fetchall()]
    for case_id in case_ids:
        cases_repo.refresh_completeness(conn, case_id, commit=False)
    conn.commit()
    return len(case_ids)


def _material_meta(conn, material_ids: list[int]) -> dict[int, dict[str, str]]:
    """只取 id/标题/链接三件套 —— 不要用 repo.detail,那会把整页原文拉回内存。"""
    if not material_ids:
        return {}
    placeholders = ", ".join("?" for _ in material_ids)
    rows = conn.execute(
        f"SELECT id, title, source_url FROM domain_items WHERE domain = ? AND item_type = 'material' AND id IN ({placeholders})",
        (DOMAIN, *material_ids),
    ).fetchall()
    return {int(row["id"]): {"title": str(row["title"] or ""), "source_url": str(row["source_url"] or "")} for row in rows}


def main(argv: list[str] | None = None) -> int:
    from ai4sec_platform.db.session import connect

    args = list(argv if argv is not None else sys.argv[1:])
    dry_run = "--dry-run" in args
    do_seed = "--seed" in args or not any(flag in args for flag in ("--supersede", "--recompute", "--stats"))
    do_supersede = "--supersede" in args
    conn = connect()
    try:
        # 表是 SCHEMA_SQL 里的 CREATE TABLE IF NOT EXISTS:这里显式 init 一次,
        # 免得在 API 从没起过的空库上跑迁移时报"no such table"
        init_db(conn)
        if "--stats" in args:
            print(cases_repo.case_stats(conn))
            return 0
        if do_seed:
            print("seed:", seed_cases_from_events(conn, dry_run=dry_run))
        if do_supersede:
            print("superseded_events:", supersede_legacy_events(conn, dry_run=dry_run))
        if "--recompute" in args:
            print("recomputed_cases:", recompute_all(conn))
        print("stats:", cases_repo.case_stats(conn))
        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
