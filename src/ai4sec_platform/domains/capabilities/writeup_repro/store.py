"""研究复现预筛结果的读写(`writeup_repro_candidates`)。

表只存**结论**,判据在 ``screener_rules.py``(规则层)与 ``screener.py``(模型层)。
这样"这篇凭什么被判成不能复现"永远可以复算: 同一份素材 + 同一个 rule_version
重跑一遍, 结论应当逐字相同; 对不上就是代码变了, 不是数据变了。

两条写入纪律
============

1. **模型报错不落库**。``screen_material`` 返回 error 时调用方什么都不写, 这一条下一轮
   会被重新挑出来。把它记成 ``no_poc`` 是最难发现的一类谎 —— 文章明明有 PoC, 库里却写着
   "没有", 而且看起来和真的没区别(2026-10-29 降级评审灌 1941 条空壳的同型事故)。
2. **``rule_version`` 不同的行视为"还没筛过"**。规则层改了以后旧结论自动失效、重筛一遍,
   而不是让两套口径的行混在同一张表里比通过率。
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Iterable

DOMAIN = "vulnerabilities"
ITEM_TYPE = "material"

_COLUMNS = (
    "material_id", "screenable", "reject_reason", "has_poc", "poc_lang", "poc_verified",
    "target_kind", "target_repo", "target_version", "env_hint", "claimed_effect",
    "evidence_quote", "rule_json", "screen_json", "rule_version", "model_profile",
    "screened_by", "screened_at",
)

# T1.5 才写的列。重筛时**不碰**: 那些列是后续步骤(资产命中/优先级)的结论,
# 被一次规则层升级顺手抹掉, 页面上就成了"算过又没算过"。
_RESERVED = ("asset_hit", "asset_ids", "asset_confidence", "priority", "priority_reason")


def now() -> str:
    return f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"


def pending_materials(
    conn: sqlite3.Connection,
    *,
    limit: int = 200,
    rule_version: str = "",
    material_ids: Iterable[int] | None = None,
) -> list[dict[str, Any]]:
    """还没按当前规则版本预筛过的素材。

    ``cleaned_text`` 走 ``json_extract`` 而不是把 ``payload_json`` 整列拉出来 ——
    素材 payload 平均几十到几百 KB(库里 ``search_candidate`` 的 payload 合计 7.5 GB),
    整列取回来只为读一个字段是白给内存。
    """
    sql = [
        "SELECT d.id, d.title, d.source_url, d.source, d.primary_date,",
        "       COALESCE(json_extract(d.payload_json, '$.cleaned_text'),",
        "                json_extract(d.payload_json, '$.markdown'), '') AS body",
        "  FROM domain_items d",
        "  LEFT JOIN writeup_repro_candidates c ON c.material_id = d.id",
        " WHERE d.domain = ? AND d.item_type = ? AND d.status != '已淘汰'",
        "   AND (c.material_id IS NULL OR c.rule_version != ?)",
    ]
    params: list[Any] = [DOMAIN, ITEM_TYPE, rule_version]
    ids = [int(i) for i in (material_ids or [])]
    if ids:
        sql.append(f"   AND d.id IN ({','.join('?' * len(ids))})")
        params.extend(ids)
    sql.append(" ORDER BY d.id DESC LIMIT ?")
    params.append(int(limit))
    rows = conn.execute("\n".join(sql), params).fetchall()
    return [
        {
            "id": r[0],
            "title": r[1] or "",
            "url": r[2] or "",
            "source": r[3] or "",
            "primary_date": r[4] or "",
            "cleaned_text": r[5] or "",
        }
        for r in rows
    ]


def upsert_candidate(conn: sqlite3.Connection, row: dict[str, Any]) -> None:
    """写一条预筛结论。同一条素材重筛时覆盖判定列, 保留 T1.5 的预留列。"""
    values = [row.get(col) for col in _COLUMNS]
    updates = ", ".join(f"{col} = excluded.{col}" for col in _COLUMNS if col != "material_id")
    conn.execute(
        f"INSERT INTO writeup_repro_candidates ({', '.join(_COLUMNS)}) "
        f"VALUES ({', '.join('?' * len(_COLUMNS))}) "
        f"ON CONFLICT(material_id) DO UPDATE SET {updates}",
        values,
    )


def get_candidate(conn: sqlite3.Connection, material_id: int) -> dict[str, Any] | None:
    cur = conn.execute(
        "SELECT * FROM writeup_repro_candidates WHERE material_id = ?", (int(material_id),)
    )
    names = [d[0] for d in cur.description]
    row = cur.fetchone()
    if row is None:
        return None
    out = dict(zip(names, row))
    for key in ("rule_json", "screen_json", "asset_ids"):
        try:
            out[key] = json.loads(out.get(key) or "{}")
        except (TypeError, ValueError):
            out[key] = {}
    return out


def screenable_candidates(conn: sqlite3.Connection, *, limit: int = 100) -> list[dict[str, Any]]:
    """可进复现队列的候选, 供 T2/T3 消费。"""
    rows = conn.execute(
        "SELECT material_id, target_kind, target_repo, target_version, poc_lang, claimed_effect "
        "  FROM writeup_repro_candidates WHERE screenable = 1 "
        " ORDER BY (target_repo != '') DESC, material_id DESC LIMIT ?",
        (int(limit),),
    ).fetchall()
    return [
        {
            "material_id": r[0],
            "target_kind": r[1],
            "target_repo": r[2],
            "target_version": r[3],
            "poc_lang": r[4],
            "claimed_effect": r[5],
        }
        for r in rows
    ]


def stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """预筛漏斗。页面上"为什么只有这么点能复现"要能一眼看到分母与每个拒绝桶。"""
    total = conn.execute(
        "SELECT COUNT(*) FROM domain_items WHERE domain = ? AND item_type = ? AND status != '已淘汰'",
        (DOMAIN, ITEM_TYPE),
    ).fetchone()[0]
    by_reason = {
        (reason or "screenable"): count
        for reason, count in conn.execute(
            "SELECT reject_reason, COUNT(*) FROM writeup_repro_candidates GROUP BY reject_reason"
        )
    }
    scanned = sum(by_reason.values())
    return {
        "materials_total": int(total),
        "screened": int(scanned),
        "screenable": int(by_reason.get("screenable", 0)),
        "reject_reason": {k: v for k, v in by_reason.items() if k != "screenable"},
        "pending": max(int(total) - int(scanned), 0),
    }
