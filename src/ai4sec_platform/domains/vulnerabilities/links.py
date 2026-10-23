"""案例 ↔ 文章 ↔ 漏洞模式 的确定性关联(P6a,2026-10-23)。

改造前三个页面各看各的:案例库只有洞和它的代码,模式库只有从 writeup 抽象出的模式,
素材库里则躺着那些 writeup 的正文。可这三条线在库里本来就是同一批东西 ——

  素材(`payload.cve_ids`)-- 编号相同 --> 案例(`canonical_id` / `cve_ids` / `ghsa_ids` / `aliases`)
  模式(`payload.knowledge_ids`)--> 知识(`payload.source_material_id`)--> 素材 --> 案例

第一条要**落库**:请求时现算得把 798 条素材的 payload 全解析一遍,实测 2 秒,挂在抽屉里
不可接受。所以写成 `vulnerability_case_context` 的 reference 行(空 content + `ref_item_id`,
指纹沿用 cases 模块的 `item:<id>`,同一条素材对一个洞只会有一行),provenance 用
`from_material_cve` 与继承来的 `from_legacy_event` 区分。后两条是读时 join:知识 820 条、
模式 121 条,两毫秒级。

诚实口径(页面上按这个措辞写,不夸大):
  · `from_material_cve` 证明的是「**这篇文章提到过这个编号**」,
    不是「这篇文章把这条案例讲透了」;
  · 模式 → 案例证明的是「这条案例的 CVE 出现在该模式**来源文章**里」,
    不是「这条案例参与了这个模式的抽象」。
真正的"模式有文章 + 案例有代码"的合流是 P6b。
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

DOMAIN = "vulnerabilities"
MATERIAL_LINK_PROVENANCE = "from_material_cve"


# ---------------------------------------------------------------- 小工具


def _json_value(value: Any, default: Any) -> Any:
    """`json_extract` 出来的数组是 JSON 文本,payload 里的是真 list —— 两种都收。"""
    if value is None:
        return default
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "ignore")
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return default
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return default
        return parsed if isinstance(parsed, list) else default
    return default


def _text_list(value: Any) -> list[str]:
    return [str(item).strip() for item in _json_value(value, []) if str(item).strip()]


def _id_list(value: Any) -> list[int]:
    result: list[int] = []
    for item in _json_value(value, []):
        try:
            result.append(int(item))
        except (TypeError, ValueError):
            continue
    return result


def _placeholders(values: Iterable[Any]) -> str:
    return ",".join("?" for _ in values)


# ---------------------------------------------------------------- 案例 ↔ 素材


def _case_aliases(row: sqlite3.Row) -> set[str]:
    """案例认的所有编号。素材是英文原文,编号大小写不统一,比较前一律大写。

    一个 GHSA 案例的正文里常常同时有 CVE(OSV 的 alias),所以 GHSA 案例也要把
    `cve_ids` / `aliases` 一并算进来,否则那批洞永远连不上文章。
    """
    values = [str(row["canonical_id"] or "")]
    values.extend(_text_list(row["cve_ids_json"] if "cve_ids_json" in row.keys() else None))
    values.extend(_text_list(row["ghsa_ids_json"] if "ghsa_ids_json" in row.keys() else None))
    values.extend(_text_list(row["aliases_json"] if "aliases_json" in row.keys() else None))
    return {value.strip().upper() for value in values if value.strip()}


def _material_cve_index(conn: sqlite3.Connection) -> dict[str, list[dict[str, Any]]]:
    """编号 → 提到它的素材。只取三列,正文不进内存。"""
    index: dict[str, list[dict[str, Any]]] = {}
    rows = conn.execute(
        "SELECT id, title, source_url, payload_json FROM domain_items WHERE domain = ? AND item_type = ?",
        (DOMAIN, "material"),
    )
    for row in rows:
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except (ValueError, TypeError):
            continue
        ids = {str(value).strip().upper() for value in (payload.get("cve_ids") or []) if str(value).strip()}
        if not ids:
            continue
        meta = {"item_id": int(row["id"]), "title": str(row["title"] or ""), "source_url": str(row["source_url"] or "")}
        for cve_id in ids:
            index.setdefault(cve_id, []).append(meta)
    return index


def link_cases_to_materials(conn: sqlite3.Connection, *, commit: bool = True) -> dict[str, Any]:
    """把「文章正文提到这个编号」落成案例的 reference 行。幂等,每晚全量跑(约 2 秒)。

    只写 `from_material_cve`:已经存在的 `from_legacy_event` 行不会被改来源 ——
    指纹相同(空 content + `ref_item_id`),`INSERT OR IGNORE` 直接跳过。
    """
    from ai4sec_platform.domains.vulnerabilities.cases import add_context

    index = _material_cve_index(conn)
    stats = {
        "cve_ids_indexed": len(index),
        "materials_with_cve": len({meta["item_id"] for metas in index.values() for meta in metas}),
        "cases_scanned": 0,
        "cases_linked": 0,
        "links_created": 0,
    }
    rows = conn.execute(
        "SELECT id, canonical_id, cve_ids_json, ghsa_ids_json, aliases_json FROM vulnerability_cases "
        "WHERE COALESCE(status, '') <> 'superseded'"
    ).fetchall()
    for row in rows:
        stats["cases_scanned"] += 1
        rows_to_add: list[dict[str, Any]] = []
        seen: set[int] = set()
        for alias in _case_aliases(row):
            for material in index.get(alias, []):
                material_id = int(material["item_id"])
                if material_id in seen:
                    continue
                seen.add(material_id)
                rows_to_add.append({
                    "context_type": "reference",
                    "provenance": MATERIAL_LINK_PROVENANCE,
                    # 正文不进上下文表:抽屉按 ref_item_id 去读原素材,避免重演威胁域 800MB 的坑。
                    "content": "",
                    "ref_item_id": material_id,
                    "label": material["title"] or f"素材 #{material_id}",
                    "source_url": material["source_url"],
                })
        if not rows_to_add:
            continue
        inserted = add_context(conn, int(row["id"]), rows_to_add, actor="case_material_link", commit=False)
        if inserted:
            stats["cases_linked"] += 1
            stats["links_created"] += inserted
    if commit:
        conn.commit()
    return stats


# ---------------------------------------------------------------- 案例 → 模式


def _related_knowledge_ids(conn: sqlite3.Connection, material_ids: list[int], aliases: set[str]) -> list[int]:
    clauses: list[str] = []
    params: list[Any] = []
    if material_ids:
        clauses.append(f"json_extract(payload_json, '$.source_material_id') IN ({_placeholders(material_ids)})")
        params.extend(material_ids)
    if aliases:
        alias_list = sorted(aliases)
        clauses.append(
            "EXISTS (SELECT 1 FROM json_each(CASE WHEN json_type(payload_json, '$.cve_ids') = 'array' "
            "THEN json_extract(payload_json, '$.cve_ids') ELSE '[]' END) e "
            f"WHERE upper(e.value) IN ({_placeholders(alias_list)}))"
        )
        params.extend(alias_list)
    if not clauses:
        return []
    rows = conn.execute(
        "SELECT id FROM domain_items WHERE domain = ? AND item_type = ? AND (" + " OR ".join(clauses) + ")",
        (DOMAIN, "knowledge", *params),
    )
    return [int(row[0]) for row in rows]


def patterns_for_case(conn: sqlite3.Connection, case_row: sqlite3.Row) -> list[dict[str, Any]]:
    """这条案例属于哪些模式。

    判据只有一条:**该案例关联的文章,同时是某些知识条目的来源素材;这些知识条目又被
    用在了某个模式的抽象里**。所以它回答的是「这篇文章参与抽象过的那类洞」,不是
    「模型认出了这条案例属于该模式」—— 后者要等 P6b 用代码证据去判。
    """
    case_id = int(case_row["id"])
    material_rows = conn.execute(
        "SELECT DISTINCT ref_item_id FROM vulnerability_case_context WHERE case_id = ? AND ref_item_id > 0",
        (case_id,),
    ).fetchall()
    material_ids = [int(row[0]) for row in material_rows]
    knowledge_ids = _related_knowledge_ids(conn, material_ids, _case_aliases(case_row))
    if not knowledge_ids:
        return []
    rows = conn.execute(
        "SELECT id, title, json_extract(payload_json, '$.pattern_name') AS pattern_name, "
        "json_extract(payload_json, '$.pattern_id') AS pattern_ref, "
        "json_extract(payload_json, '$.cwe_ids') AS cwe_ids, "
        "json_extract(payload_json, '$.member_count') AS member_count, "
        "json_extract(payload_json, '$.confidence') AS confidence "
        "FROM domain_items WHERE domain = ? AND item_type = 'vulnerability_pattern' "
        "AND EXISTS (SELECT 1 FROM json_each(CASE WHEN json_type(payload_json, '$.knowledge_ids') = 'array' "
        "THEN json_extract(payload_json, '$.knowledge_ids') ELSE '[]' END) k "
        f"WHERE k.value IN ({_placeholders(knowledge_ids)})) "
        "ORDER BY member_count DESC, id DESC",
        (DOMAIN, *knowledge_ids),
    ).fetchall()
    return [
        {
            "id": int(row["id"]),
            "pattern_ref": str(row["pattern_ref"] or ""),
            "pattern_name": str(row["pattern_name"] or row["title"] or ""),
            "cwe_ids": _text_list(row["cwe_ids"]),
            "member_count": int(row["member_count"] or 0),
            "confidence": float(row["confidence"]) if row["confidence"] is not None else None,
        }
        for row in rows
    ]


# ---------------------------------------------------------------- 模式 → 案例


def cases_for_pattern(conn: sqlite3.Connection, item_id: int, *, limit: int = 50) -> dict[str, Any] | None:
    """模式的实例案例。模式 → 知识 → 它们各自的来源素材 / 编号 → 挂在这些素材上或编号相同的案例。"""
    row = conn.execute(
        "SELECT id, title, payload_json FROM domain_items WHERE domain = ? AND item_type = ? AND id = ?",
        (DOMAIN, "vulnerability_pattern", int(item_id)),
    ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except (ValueError, TypeError):
        payload = {}
    pattern_name = str(payload.get("pattern_name") or row["title"] or "")
    knowledge_ids = _id_list(payload.get("knowledge_ids"))

    material_ids: set[int] = set()
    cve_ids: set[str] = set()
    if knowledge_ids:
        for knowledge in conn.execute(
            "SELECT json_extract(payload_json, '$.source_material_id') AS material_id, "
            "json_extract(payload_json, '$.cve_ids') AS cves "
            "FROM domain_items WHERE domain = ? AND item_type = ? "
            f"AND id IN ({_placeholders(knowledge_ids)})",
            (DOMAIN, "knowledge", *knowledge_ids),
        ):
            if knowledge["material_id"] is not None:
                material_ids.add(int(knowledge["material_id"]))
            cve_ids.update(value.upper() for value in _text_list(knowledge["cves"]))

    result: dict[str, Any] = {
        "pattern_id": int(item_id),
        "pattern_name": pattern_name,
        "knowledge_count": len(knowledge_ids),
        "material_count": len(material_ids),
        "cve_count": len(cve_ids),
        "count": 0,
        "note": "",
        "items": [],
    }
    if not material_ids and not cve_ids:
        result["note"] = (
            "该模式没有可追溯的来源素材(知识条目已被清理或没有编号),列不出实例。"
            if knowledge_ids else "该模式没有记录来源知识条目,列不出实例。"
        )
        return result

    clauses: list[str] = []
    params: list[Any] = []
    if material_ids:
        clauses.append(
            "EXISTS (SELECT 1 FROM vulnerability_case_context x WHERE x.case_id = c.id "
            "AND x.context_type = 'reference' "
            f"AND x.ref_item_id IN ({_placeholders(sorted(material_ids))}))"
        )
        params.extend(sorted(material_ids))
    if cve_ids:
        cve_list = sorted(cve_ids)
        placeholders = _placeholders(cve_list)
        clauses.append(f"upper(c.canonical_id) IN ({placeholders})")
        params.extend(cve_list)
        clauses.append(f"EXISTS (SELECT 1 FROM json_each(c.cve_ids_json) e WHERE upper(e.value) IN ({placeholders}))")
        params.extend(cve_list)
        clauses.append(f"EXISTS (SELECT 1 FROM json_each(c.aliases_json) e WHERE upper(e.value) IN ({placeholders}))")
        params.extend(cve_list)

    where = " OR ".join(clauses)
    rows = conn.execute(
        "SELECT c.id, c.canonical_id, c.id_kind, c.title, c.severity, c.cvss_score, c.published_at, c.source, "
        "c.has_patch, c.has_vuln_site, c.has_dataflow, c.context_completeness "
        "FROM vulnerability_cases c WHERE " + where +
        " ORDER BY c.published_at DESC, c.id DESC LIMIT ?",
        (*params, max(int(limit), 1)),
    ).fetchall()
    # 条数单独 COUNT:截断之后 len(items) 只是本页的页长,拿它当实例数会把 40 条说成 5 条
    # (2026-09-11 那批 new_case_count 的同一条教训)。
    total = int(conn.execute(
        "SELECT COUNT(*) FROM vulnerability_cases c WHERE " + where, params
    ).fetchone()[0])
    items = [
        {
            "id": int(case["id"]),
            "canonical_id": str(case["canonical_id"] or ""),
            "id_kind": str(case["id_kind"] or ""),
            "title": str(case["title"] or ""),
            "severity": str(case["severity"] or ""),
            "cvss_score": float(case["cvss_score"]) if case["cvss_score"] is not None else None,
            "published_at": str(case["published_at"] or ""),
            "source": str(case["source"] or ""),
            "has_patch": int(case["has_patch"] or 0),
            "has_vuln_site": int(case["has_vuln_site"] or 0),
            "has_dataflow": int(case["has_dataflow"] or 0),
            "context_completeness": float(case["context_completeness"] or 0),
            "why": "cve",
            "materials": [],
        }
        for case in rows
    ]

    # 哪些案例是通过素材挂上的(而不是只靠编号相同),以及挂的是哪几篇文章。
    if items and material_ids:
        case_ids = [item["id"] for item in items]
        material_ids_sorted = sorted(material_ids)
        link_rows = conn.execute(
            "SELECT DISTINCT case_id, ref_item_id FROM vulnerability_case_context "
            f"WHERE context_type = 'reference' AND case_id IN ({_placeholders(case_ids)}) "
            f"AND ref_item_id IN ({_placeholders(material_ids_sorted)})",
            (*case_ids, *material_ids_sorted),
        ).fetchall()
        by_case: dict[int, list[int]] = {}
        for link in link_rows:
            by_case.setdefault(int(link["case_id"]), []).append(int(link["ref_item_id"]))
        title_rows = conn.execute(
            f"SELECT id, title FROM domain_items WHERE domain = ? AND item_type = 'material' "
            f"AND id IN ({_placeholders(material_ids_sorted)})",
            (DOMAIN, *material_ids_sorted),
        ).fetchall()
        titles = {int(title_row["id"]): str(title_row["title"] or "") for title_row in title_rows}
        for item in items:
            matched = by_case.get(item["id"], [])
            if matched:
                item["why"] = "material"
                item["materials"] = [{"item_id": mid, "title": titles.get(mid, "")} for mid in matched[:3]]

    result["count"] = total
    result["items"] = items
    if not items:
        result["note"] = (
            "这个模式的来源文章里,目前没有点名库里已有的案例 —— 模式本身不受影响,只是还没有落地实例。"
        )
    return result
