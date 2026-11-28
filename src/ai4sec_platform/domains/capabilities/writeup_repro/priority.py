"""T1.5:先复现哪一篇 —— 按"和我司资产/生态的关系"排 P0/P1/P2。

口径来自实施文档 §4·5(2026-11-10 定稿), 这里只实现、不改判据:

| 档 | 条件 | 说明 |
|---|---|---|
| **P0** | 命中资产/生态(四条路径任一) | 优先复现 |
| **P1** | 未命中, 但 PoC + 仓库 + 版本都齐 | 能直接跑 |
| **P2** | 其余可复现 | 排队 |

四条路径(A2 是现阶段唯一有量的通道):

- **A1 强关联**: writeup 的 CVE 出现在 `threat_links`(direct/inferred)关联仓的 CVE 清单里;
- **A2 生态命中**: writeup 的 CVE 出现在**任意跟踪仓**的 CVE 清单里 —— 文案只能说
  "该编号出现在某生态仓的公告/issue 里", **不能说"我司产品受影响"**(仓里的 CVE 混着自己带的
  第三方依赖的洞, 把关联说成影响就是撒谎);
- **C** 用户登记的盯源(`vulnerability_case_sources`, tracked_package / tracked_repo)命中;
- **D** 项目清单(`vulnerability_projects.packages_json`)命中。

两条必须守住的话(§4·5.4):**① 资产命中不是唯一通道** —— A1 现在只有个位数 CVE, 队列主力仍是
P1/P2, 页面要如实显示"暂无资产命中"而不是让队列看起来像坏了;**② 缺的是数据不是逻辑** —— 没有
SBOM 之前, 任何"和我司产品相关"的排序都只是推断。
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from typing import Any

#: CVE 索引与关联表的缓存时间。两次预筛之间隔着几分钟到几小时, 600 秒足够避免每次重算,
#: 又不至于让新抓的威胁数据一直不可见。
INDEX_TTL_SECONDS = 600

_CACHE: dict[str, Any] = {"at": 0.0, "cve": {}, "links": {}, "assets": {}, "sources": [], "projects": []}


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9./_:@-]+", "", str(text or "").strip().lower())


def refresh(conn: sqlite3.Connection) -> dict[str, Any]:
    """重建索引(威胁仓的 CVE、资产↔仓关联、盯源、项目包)。"""
    cve: dict[str, list[tuple[int, str]]] = {}
    for row in conn.execute(
        "SELECT id, payload_json FROM domain_items"
        " WHERE domain = 'threats' AND item_type = 'target'"
        "   AND json_extract(payload_json, '$.cve_count') > 0"
    ):
        try:
            payload = json.loads(row[1] or "{}")
        except (TypeError, ValueError):
            continue
        repo = " ".join(str(payload.get(k) or "") for k in ("org", "name")).strip() or f"item:{row[0]}"
        for item in payload.get("cves") or []:
            if not isinstance(item, dict):
                continue
            key = str(item.get("cve_id") or "").strip().upper()
            if key:
                cve.setdefault(key, []).append((int(row[0]), repo))

    links: dict[int, list[tuple[int, str]]] = {}
    for row in conn.execute(
        "SELECT repo_id, asset_id, confidence FROM threat_links"
        " WHERE confidence IN ('direct', 'inferred')"
    ):
        links.setdefault(int(row[0]), []).append((int(row[1]), str(row[2])))

    sources = [
        {"kind": str(r[0]), "identifier": str(r[1])}
        for r in conn.execute(
            "SELECT kind, identifier FROM vulnerability_case_sources WHERE enabled = 1"
        )
    ]
    projects = [
        {"slug": str(r[0]), "packages": json.loads(r[1] or "[]")}
        for r in conn.execute(
            "SELECT slug, packages_json FROM vulnerability_projects WHERE enabled = 1"
        )
    ]

    _CACHE.update({"at": time.time(), "cve": cve, "links": links,
                   "assets": {}, "sources": sources, "projects": projects})
    return _CACHE


def _ensure(conn: sqlite3.Connection) -> dict[str, Any]:
    if not _CACHE["cve"] or time.time() - float(_CACHE["at"]) > INDEX_TTL_SECONDS:
        refresh(conn)
    return _CACHE


def _asset_name(conn: sqlite3.Connection, asset_id: int) -> str:
    cache = _CACHE.setdefault("assets", {})
    if asset_id not in cache:
        row = conn.execute(
            "SELECT title FROM domain_items WHERE id = ? AND domain = 'threats'", (int(asset_id),)
        ).fetchone()
        cache[asset_id] = str(row[0]) if row else f"asset:{asset_id}"
    return cache[asset_id]


def _project_or_source_hit(conn: sqlite3.Connection, candidate: dict[str, Any]) -> tuple[list[str], str]:
    """C/D:用户自己登记的盯源与项目清单。两只表都可能是空的 —— 命中 0 条是**事实**, 不是错误。"""
    product = _norm(candidate.get("target_product"))
    repo = _norm(candidate.get("target_repo"))
    repo_tail = repo.split("/")[-1] if repo else ""
    if not (product or repo_tail):
        return [], ""
    names = {n for n in (product, repo_tail) if n}
    hits: list[str] = []
    cache = _ensure(conn)
    for source in cache["sources"]:
        identifier = _norm(source["identifier"])
        if any(name and (name == identifier.split(":")[-1] or name in identifier) for name in names):
            hits.append(f"盯源 {source['identifier']}")
    for project in cache["projects"]:
        for package in project.get("packages") or []:
            name = _norm(package.get("name") if isinstance(package, dict) else package)
            if name and any(n == name or n in name for n in names):
                hits.append(f"项目 {project['slug']}")
    return sorted(set(hits)), "declared" if hits else ""


def compute(conn: sqlite3.Connection, candidate: dict[str, Any]) -> dict[str, Any]:
    """算一条候选的优先级。返回要写回 ``writeup_repro_candidates`` 的五个字段。"""
    if not int(candidate.get("screenable") or 0):
        return {"asset_hit": 0, "asset_ids": "", "asset_confidence": "", "priority": "",
                "priority_reason": "不可复现，不参与排序"}

    cache = _ensure(conn)
    cve = str(candidate.get("target_cve") or "").strip().upper()

    # A1 / A2:按 CVE 命中(仓库 URL 直接匹配是 0 —— 威胁侧是 gitcode/atomgit, writeup 多是 GitHub)
    if cve and cve in cache["cve"]:
        repos = cache["cve"][cve]
        linked: list[tuple[str, str]] = []      # (asset 名, 置信度)
        for item_id, repo_name in repos:
            for asset_id, confidence in cache["links"].get(item_id, []):
                linked.append((_asset_name(conn, asset_id), confidence))
        if linked:
            confidence = "direct" if any(conf == "direct" for _, conf in linked) else "inferred"
            names = sorted({name for name, _ in linked})
            return {
                "asset_hit": 1,
                "asset_ids": "、".join(names[:5]),
                "asset_confidence": confidence,
                "priority": "P0",
                "priority_reason": f"命中资产（{confidence}）：{'、'.join(names[:3])}",
            }
        eco = sorted({repo for _, repo in repos})
        return {
            "asset_hit": 1,
            "asset_ids": "、".join(eco[:5]),
            "asset_confidence": "ecosystem",
            "priority": "P0",
            "priority_reason": f"{cve} 出现在生态仓公告里：{'、'.join(eco[:3])}（不代表我司产品受影响）",
        }

    declared, kind = _project_or_source_hit(conn, candidate)
    if declared:
        return {
            "asset_hit": 1,
            "asset_ids": "、".join(declared[:5]),
            "asset_confidence": kind,
            "priority": "P0",
            "priority_reason": f"命中用户登记：{'、'.join(declared[:3])}",
        }

    # P1:没有资产关系, 但 PoC / 仓库 / 版本齐全 —— 现在队列的主力就是这一档
    if int(candidate.get("has_poc") or 0) and candidate.get("target_repo") and candidate.get("target_version"):
        return {"asset_hit": 0, "asset_ids": "", "asset_confidence": "", "priority": "P1",
                "priority_reason": "未命中资产，但 PoC、仓库与版本齐全"}

    return {"asset_hit": 0, "asset_ids": "", "asset_confidence": "", "priority": "P2",
            "priority_reason": "未命中资产，且 PoC/仓库/版本不全"}


def assign(conn: sqlite3.Connection, *, material_ids: list[int] | None = None,
           only_empty: bool = False) -> dict[str, int]:
    """给候选回填优先级。**只写这五个字段**, 不动预筛结论。"""
    where = ["1 = 1"]
    params: list[Any] = []
    if material_ids:
        where.append("material_id IN (%s)" % ",".join("?" * len(material_ids)))
        params.extend(int(x) for x in material_ids)
    if only_empty:
        where.append("(priority IS NULL OR priority = '')")
    rows = conn.execute(
        "SELECT material_id, screenable, has_poc, target_repo, target_version, target_cve, target_product"
        f" FROM writeup_repro_candidates WHERE {' AND '.join(where)}", params,
    ).fetchall()
    counts = {"P0": 0, "P1": 0, "P2": 0, "": 0}
    for row in rows:
        item = {"material_id": row[0], "screenable": row[1], "has_poc": row[2],
                "target_repo": row[3], "target_version": row[4], "target_cve": row[5],
                "target_product": row[6]}
        result = compute(conn, item)
        conn.execute(
            "UPDATE writeup_repro_candidates SET asset_hit = ?, asset_ids = ?, asset_confidence = ?,"
            " priority = ?, priority_reason = ? WHERE material_id = ?",
            (result["asset_hit"], result["asset_ids"], result["asset_confidence"],
             result["priority"], result["priority_reason"], int(item["material_id"])),
        )
        counts[result["priority"]] = counts.get(result["priority"], 0) + 1
    conn.commit()
    return counts
