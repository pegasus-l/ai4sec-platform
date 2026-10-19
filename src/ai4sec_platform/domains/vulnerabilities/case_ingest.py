"""P3 采集链路的**领域逻辑**:把外部源拿到的东西写进案例库。

网络一律由调用方(流水线步骤)注入成可调用对象,这里只做"选谁、写什么、怎么幂等"。
这么切是为了能拿内存库跑单测 —— 采集步最怕的是"跑起来没报错,库里写了一堆假数据",
而那种错只有在库里看得见,不在 HTTP 层。

三条口径:

1. **只填空缺、只取并集。** NVD 的分数不会被 OSV 的 GHSA 级别覆盖,研究文章给的标题不会被
   NVD 描述覆盖(见 `_keep_existing_title`)。重新富化只应增补,不该把已收集的东西抹掉。
2. **"检查过了但没结果"要留痕。** `osv_checked_at` / `patch_checked_at` 写在 payload 里,
   否则每一晚都会把同一批查不到的洞重新查一遍;同时它们是**有期限的**(默认 7 天),
   因为实测 OSV 对刚公开的洞命中率只有 20%,T+30 才会涨上来 —— 一次查不到不等于永远没有。
3. **自动采集永不覆盖人工内容。** 落到 `upsert_case` 的 `manual_owned` 分支与
   `add_context` 的 `INSERT OR IGNORE` 上,这里不需要额外判断。
"""

from __future__ import annotations

import datetime
import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.vulnerabilities import case_sources
from ai4sec_platform.domains.vulnerabilities import cases as cases_repo

# 单条案例最多留多少条引用。NVD 有些洞挂 30+ 条厂商公告,不封顶会让 references_json 失控
MAX_REFERENCES = 50
# 单个补丁最多存多少字符。超过这个量级的 diff 基本是重构/依赖锁文件,不是漏洞修复本身
MAX_PATCH_CHARS = 200_000
# "查过但没结果"的复查间隔。OSV 对 T+0 的洞覆盖只有 20%,T+30 才有意义
RECHECK_DAYS = 7


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _cutoff(days: int = RECHECK_DAYS) -> str:
    return (_now() - datetime.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── NVD 窗口 → 案例 ──────────────────────────────────────────────────────────

def apply_nvd_items(
    conn: sqlite3.Connection,
    items: list[dict[str, Any]],
    *,
    min_cvss: float = 7.0,
    max_cases: int = 1500,
    actor: str = "case_ingest",
    only_existing: bool = False,
    published_since: str = "",
) -> dict[str, Any]:
    """把一批 NVD `{"cve": {...}}` 写进案例库。返回统计。

    `only_existing=True` 用于**回溯**:只更新库里已有的洞,不因为回溯把 30 天的历史全补建一遍
    (那会让案例库在某一天突然胀几万条)。回溯需要补建的情况走 `FetchNewCveWindowStep` 的
    宽窗口,不走这里。

    `max_cases` 是尖峰保护:实测 2026-10-13 一天公开了 2308 条(平日 5 倍),没上限的话
    那一晚会把库冲出一整天的量。超了按 CVSS 从高到低取,保证丢掉的是低分的。
    """
    stats: dict[str, Any] = {"scanned": 0, "matched": 0, "created": 0, "updated": 0, "capped": 0, "skipped_existing": 0, "skipped_old": 0}
    prepared: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        cve = item.get("cve") if isinstance(item.get("cve"), dict) else item
        stats["scanned"] += 1
        if published_since and case_sources.published_at(cve) and case_sources.published_at(cve) < published_since:
            # 回溯步会捞到"很久以前公开、最近刚补分"的洞 —— 那是历史存量,不该进本期的案例库
            stats["skipped_old"] += 1
            continue
        fields = case_sources.nvd_case_fields(cve, min_cvss=min_cvss)
        if fields is None:
            continue
        prepared.append(fields)
    stats["matched"] = len(prepared)
    if max_cases and len(prepared) > max_cases:
        prepared.sort(key=lambda fields: float(fields.get("cvss_score") or 0), reverse=True)
        stats["capped"] = len(prepared) - max_cases
        prepared = prepared[:max_cases]
    for fields in prepared:
        canonical_id = str(fields["canonical_id"])
        existing = conn.execute(
            "SELECT id, title FROM vulnerability_cases WHERE canonical_id = ?", (canonical_id,)
        ).fetchone()
        if existing is None and only_existing:
            stats["skipped_existing"] += 1
            continue
        _keep_existing_title(fields, existing, canonical_id)
        # source 单独传:更新已有案例时**保留它原来怎么进来的**(legacy_event / manual_added),
        # 只有新建行才落 'nvd'。否则一夜之间 896 条存量案例的来源全变成"自动采集"。
        source = fields.pop("source", "nvd")
        result = cases_repo.upsert_case(
            conn,
            actor=actor,
            source=source,
            status="active",
            payload={"nvd_ingested_at": utc_now()},
            **fields,
        )
        stats["created" if result["created"] else "updated"] += 1
    return stats


def _keep_existing_title(fields: dict[str, Any], existing: Any, canonical_id: str) -> None:
    """已有人类可读标题时,不要用 NVD 的 `CVE-xxx · 描述` 盖掉它。

    存量 896 条里 839 条的标题取自研究文章(`CVE-xxx · <文章标题>`),那比 NVD 的
    第一句描述信息量大。标题为空、或只是 id 本身(说明从没取到过好标题)时才用 NVD 的。
    """
    if existing is None:
        return
    current = str(existing["title"] or "").strip()
    if current and current != canonical_id:
        fields.pop("title", None)


# ── OSV 富化 ─────────────────────────────────────────────────────────────────

def cases_needing_osv(conn: sqlite3.Connection, *, limit: int = 400, recheck_days: int = RECHECK_DAYS) -> list[sqlite3.Row]:
    """挑出该去 OSV 查的案例:从没查过的最优先,查过且超过 `recheck_days` 的排后面。"""
    return conn.execute(
        "SELECT * FROM vulnerability_cases "
        "WHERE status IN ('active', 'pending_fetch') AND ("
        "  json_extract(payload_json, '$.osv_checked_at') IS NULL"
        "  OR json_extract(payload_json, '$.osv_checked_at') < ?) "
        "ORDER BY (json_extract(payload_json, '$.osv_checked_at') IS NULL) DESC, published_at DESC, id DESC "
        "LIMIT ?",
        (_cutoff(recheck_days), max(1, int(limit))),
    ).fetchall()


def apply_osv_result(conn: sqlite3.Connection, case: sqlite3.Row, payload: dict[str, Any], *, extra: dict[str, Any] | None = None, actor: str = "case_ingest") -> dict[str, Any]:
    """OSV 命中:合并别名/受影响范围/引用,并在**没有更强来源**时补 CVSS 向量与严重度。

    OSV 的 `database_specific.severity` 是 GHSA 的分级(到 MODERATE 一档),比 NVD 的
    baseSeverity 粗;所以只在案例当前没有严重度时才用它。
    """
    payload = case_sources.merge_osv_payloads(payload, extra)
    existing = cases_repo.serialize_case(case)
    fields = case_sources.osv_fields(payload)
    fields.pop("fix_urls", None)
    fields.pop("osv_id", None)
    for key in ("severity", "cvss_vector", "summary", "published_at", "modified_at"):
        if str(fields.get(key) or "").strip() and str(existing.get(key) or "").strip():
            fields.pop(key, None)
    merged = list(dict.fromkeys([*(existing.get("references") or []), *(fields.get("references") or [])]))
    fields["references"] = merged[:MAX_REFERENCES]
    fields["canonical_id"] = str(existing["canonical_id"])
    fields["id_kind"] = str(existing["id_kind"])
    result = cases_repo.upsert_case(
        conn,
        actor=actor,
        status="active",
        payload={"osv_checked_at": utc_now(), "osv_status": "found", "osv_summary_present": bool(fields.get("summary"))},
        **fields,
    )
    return {
        "case_id": int(result["case_id"]),
        "created": bool(result["created"]),
        "ghsa": bool(fields.get("ghsa_ids")),
        "affected": bool(fields.get("affected_products")),
    }


def mark_osv_missing(conn: sqlite3.Connection, case_id: int, *, status: str = "not_found") -> None:
    """OSV 没有这条记录:只留痕,不动 updated_at、不改 status。

    不改 status 是有意的:一个查不到任何外部数据的洞,状态仍是 `pending_fetch`
    (意思是"还没有下文"),而不是 `active`。页面上的"待抓取"计数因此是诚实的。
    """
    _merge_payload(conn, case_id, {"osv_checked_at": utc_now(), "osv_status": status})


# ── 补丁 diff ────────────────────────────────────────────────────────────────

def cases_needing_patch(conn: sqlite3.Connection, *, limit: int = 120, recheck_days: int = RECHECK_DAYS) -> list[sqlite3.Row]:
    """挑出没有补丁、且该重试的案例。高分优先 —— 补丁有限,先花在最值钱的洞上。"""
    return conn.execute(
        "SELECT c.* FROM vulnerability_cases c "
        "WHERE c.status IN ('active', 'pending_fetch') "
        "  AND NOT EXISTS (SELECT 1 FROM vulnerability_case_context x WHERE x.case_id = c.id AND x.context_type = 'patch_diff') "
        "  AND (json_extract(c.payload_json, '$.patch_checked_at') IS NULL "
        "       OR json_extract(c.payload_json, '$.patch_checked_at') < ?) "
        "ORDER BY (json_extract(c.payload_json, '$.patch_checked_at') IS NULL) DESC, "
        "         (c.cvss_score IS NULL), c.cvss_score DESC, c.id DESC "
        "LIMIT ?",
        (_cutoff(recheck_days), max(1, int(limit))),
    ).fetchall()


def patch_candidates_for(case: sqlite3.Row) -> list[dict[str, str]]:
    return case_sources.patch_candidates(repo.loads(case["references_json"], []) or [])


def apply_patch(conn: sqlite3.Connection, case_id: int, candidate: dict[str, str], diff: str, *, actor: str = "case_ingest") -> int:
    """写入一条 patch_diff 上下文。返回真正新增的行数(0 = 同一 commit 已经存过)。"""
    rows = [{
        "context_type": "patch_diff",
        "provenance": "from_patch",
        "repo": candidate.get("repo", ""),
        "commit_sha": candidate.get("commit_sha", ""),
        "file_path": case_sources.first_changed_file(diff),
        "content": str(diff)[:MAX_PATCH_CHARS],
        "source_url": candidate.get("url", ""),
        "label": f"{candidate.get('repo', '')} {str(candidate.get('commit_sha') or '')[:12]}".strip(),
    }]
    inserted = cases_repo.add_context(conn, int(case_id), rows, actor=actor, commit=False)
    conn.commit()
    return inserted


def mark_patch_checked(conn: sqlite3.Connection, case_id: int, *, status: str) -> None:
    _merge_payload(conn, int(case_id), {"patch_checked_at": utc_now(), "patch_status": status})


# ── 杂项 ─────────────────────────────────────────────────────────────────────

def pending_case_ids(conn: sqlite3.Connection, *, limit: int = 50) -> list[str]:
    """人工添加的"按 ID 自动抓"案例(它们停在 pending_fetch,没有任何外部数据)。

    存量迁移来的 896 条也是 pending_fetch,但它们不是人工加的 —— 用 `source != 'legacy_event'`
    区分,免得每晚会去 NVD 逐条查 896 个老洞(那是 896 次请求,Scheduler 会跑一整夜)。
    """
    rows = conn.execute(
        "SELECT canonical_id FROM vulnerability_cases "
        "WHERE status = 'pending_fetch' AND id_kind = 'cve' AND source != 'legacy_event' "
        "ORDER BY id LIMIT ?",
        (max(1, int(limit)),),
    ).fetchall()
    return [str(row["canonical_id"]) for row in rows]


def _merge_payload(conn: sqlite3.Connection, case_id: int, extra: dict[str, Any]) -> None:
    """只合并 payload_json,不碰 updated_at —— "我们查过了"不是"这条案例更新了"。

    页面列表按 updated_at 排序,如果每次空查都刷新它,那一批查不到东西的洞会永远顶在最前面。
    """
    row = conn.execute("SELECT payload_json FROM vulnerability_cases WHERE id = ?", (int(case_id),)).fetchone()
    if row is None:
        raise ValueError("案例不存在")
    current = repo.loads(row["payload_json"], {}) or {}
    current.update(extra)
    conn.execute("UPDATE vulnerability_cases SET payload_json = ? WHERE id = ?", (repo.dumps(current), int(case_id)))
    conn.commit()


def ingest_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """采集侧的自查数字:哪一步收得多、哪一步空转。跑完看这个判断是不是白跑。"""
    return {
        "cases": cases_repo.case_stats(conn),
        "osv_checked": int(conn.execute("SELECT COUNT(*) FROM vulnerability_cases WHERE json_extract(payload_json, '$.osv_checked_at') IS NOT NULL").fetchone()[0]),
        "osv_found": int(conn.execute("SELECT COUNT(*) FROM vulnerability_cases WHERE json_extract(payload_json, '$.osv_status') = 'found'").fetchone()[0]),
        "patch_checked": int(conn.execute("SELECT COUNT(*) FROM vulnerability_cases WHERE json_extract(payload_json, '$.patch_checked_at') IS NOT NULL").fetchone()[0]),
        "with_patch": int(conn.execute("SELECT COUNT(DISTINCT case_id) FROM vulnerability_case_context WHERE context_type = 'patch_diff'").fetchone()[0]),
    }
