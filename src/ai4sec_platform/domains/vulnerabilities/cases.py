"""漏洞案例库:以**一个个单独的洞**为主键(CVE / GHSA / OSV / oss:<repo>#<ref> / manual:*)。

与旧的 `item_type='event'` 的根本区别:event 是"从素材聚合出来的主题",一个事件可能挂十几条
无关素材、也可能根本不含 CVE(存量 524 条里 233 条是无 CVE 的知识主题);案例库反过来 ——
**洞是实体,素材是它的证据**。表结构与选型理由见 db/models/__init__.py 里那段注释。

三条贯穿全模块的规矩(计划第七节"诚实性硬规则",写在这里而不是靠调用方自觉):

1. `provenance` 必填。每条上下文都要说清来源 —— `from_osv`/`from_patch` 是外部事实、
   `llm_extracted` 是模型推断、`manual_added` 是人写的,前端要用不同视觉区分。
2. `llm_extracted` ⇒ `confidence` 必填。模型说的话必须带自评置信度,否则无法与事实分层。
3. 自动采集**永不覆盖** `manual_added` 的上下文行,也**永不覆盖**人工案例的元数据。
   实现上靠两件事:上下文一律 `INSERT OR IGNORE`(靠 UNIQUE 约束去重,天然不覆盖),
   以及 `upsert_case` 里对 `source='manual_added'` 的案例只填空缺。

注意本模块**不 import 任何 pipeline / connector**,只依赖 db 与 core —— 它同时被 API
(人工添加/编辑)、迁移脚本(存量 event 抽种子)和 P3 的采集步调用,不要把采集逻辑塞进来。
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from typing import Any, Iterable

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo

CASE_STATUSES = ("pending_fetch", "draft", "active", "superseded")
ID_KINDS = ("cve", "ghsa", "osv", "oss", "custom")
CONTEXT_TYPES = ("reference", "patch_diff", "vuln_site", "dataflow", "caller_snippet", "manual_note")
# llm_extracted_unverified: 模型给的行号落在补丁 hunk 之外(见 P4a 的规则校验),降级保留但标出来
# from_source: 从仓库**修复前源码**里直接读到的行(2026-10-19 P4b 的调用方代码)。它是外部事实,
#             但锚定的是 base commit(仓库里没有一个可直接引用的"父提交"指针),所以与 from_patch 分开记。
PROVENANCES = ("from_nvd", "from_osv", "from_patch", "from_source", "from_legacy_event", "from_material_cve", "llm_extracted", "llm_extracted_unverified", "manual_added")
AUTO_PROVENANCES = ("from_nvd", "from_osv", "from_patch", "from_source")
# 需要置信度的来源:模型推断的两档
LLM_PROVENANCES = ("llm_extracted", "llm_extracted_unverified")
MANUAL_SOURCE = "manual_added"


def human_added_sql(alias: str = "") -> str:
    """「这条洞是人登记的」的唯一判据。`source` 单独不够用。

    按 ID 自动抓进来时 `source='manual_id'`,而 NVD/OSV 富化后它不会变成 nvd(upsert 只在
    source 为空时才写),看起来还像人加的;但完全手填的是 `manual_added`。真正跨两条路径、
    跨富化都还留着的痕迹是 `payload.added_via` —— 只有 `POST /cases` 会写它。
    统计、筛选、采集排队三处必须用同一个判据,否则"我刚加的那个洞"在页面上数不到。
    """
    prefix = f"{alias}." if alias else ""
    return f"({prefix}source = 'manual_added' OR json_extract({prefix}payload_json, '$.added_via') IN ('auto', 'manual'))"


# "有某一格上下文"的正向筛选键 → 谓词。与 case_stats 的 context.* 四个计数同源,
# 保证点开统计数字看到的条数与数字本身一致。
HAS_PREDICATES = {
    "metadata": "metadata_complete = 1",
    "patch": "has_patch = 1",
    "vuln_site": "has_vuln_site = 1",
    "dataflow": "has_dataflow = 1",
}

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# GHSA 是 4-4-4 的 base32 小写字母数字;外部文档里常写成大写,归一成小写
_GHSA_RE = re.compile(r"GHSA-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}", re.IGNORECASE)
_OSV_RE = re.compile(r"OSV-\d{4}-\d+", re.IGNORECASE)
_OSS_RE = re.compile(r"oss:[^\s#]+#[^\s]+")
_MANUAL_RE = re.compile(r"manual:[0-9a-f]{6,40}")

# 元数据里"可被外部源覆盖"的标量列
SCALAR_FIELDS = ("title", "summary", "severity", "cvss_score", "cvss_vector", "published_at", "modified_at", "source", "source_url")
# 合并时取并集的数组列
ARRAY_FIELDS = ("cve_ids", "ghsa_ids", "cwe_ids", "aliases", "affected_products", "affected_ranges", "fixed_versions", "references", "legacy_material_ids")
# 人工可在页面上直接改的列(PATCH 白名单)
EDITABLE_FIELDS = ("title", "summary", "severity", "cvss_score", "cvss_vector", "status", *ARRAY_FIELDS)


# ── id 归一化 ────────────────────────────────────────────────────────────────

def normalize_canonical_id(raw: Any) -> dict[str, str] | None:
    """把用户贴进来的 id 归一成 {canonical_id, id_kind};认不出来返回 None。

    用 `search` 而不是 `fullmatch`,是因为人会直接粘整条 URL 或带前后的文字
    (如 "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q" 或 "见 CVE-2021-44228 的分析"),
    这属于最常见的一次性输入误差,不该让用户先自己截断。
    """
    text = str(raw or "").strip()
    if not text:
        return None
    match = _CVE_RE.search(text)
    if match:
        return {"canonical_id": match.group(0).upper(), "id_kind": "cve"}
    match = _GHSA_RE.search(text)
    if match:
        return {"canonical_id": "GHSA-" + match.group(0)[5:].lower(), "id_kind": "ghsa"}
    match = _OSV_RE.search(text)
    if match:
        return {"canonical_id": match.group(0).upper(), "id_kind": "osv"}
    match = _OSS_RE.search(text)
    if match:
        return {"canonical_id": match.group(0), "id_kind": "oss"}
    match = _MANUAL_RE.search(text)
    if match:
        return {"canonical_id": match.group(0).lower(), "id_kind": "custom"}
    return None


def manual_case_id(title: str, source_url: str = "") -> str:
    """完全手填(没有外部 id)的案例主键:**由标题+链接派生**,不是随机数。

    派生而不是随机:同一条内部 bug 被两个人各填一遍时,第二次是**重新启用**同一条案例
    (upsert 语义),而不是并排长出两条重复项 —— 与 threat_source_targets.add_target 一致。
    标题或链接改了就是另一条案例,这是这类派生键固有的代价,页面上的编辑入口会保留 canonical_id 不变。
    """
    seed = f"{str(title or '').strip()}\n{str(source_url or '').strip()}".encode("utf-8")
    return f"manual:{hashlib.sha1(seed).hexdigest()[:12]}"


# ── 行序列化 ─────────────────────────────────────────────────────────────────

def serialize_case(row: sqlite3.Row | dict[str, Any], counts: dict[str, int] | None = None) -> dict[str, Any]:
    """DB 行 → API 形态:把 *_json 列摊平成数组,别让调用方到处 json.loads。"""
    item = dict(row)
    for field in ARRAY_FIELDS:
        item[field] = repo.loads(item.pop(f"{field}_json", None), []) or []
    item["payload"] = repo.loads(item.pop("payload_json", None), {}) or {}
    item["is_manual"] = str(item.get("source") or "") == MANUAL_SOURCE or str(item["payload"].get("added_via") or "") in {"auto", "manual"}
    if counts is not None:
        item["context_counts"] = counts
        item["context_total"] = sum(counts.values())
    return item


def _case_counts(conn: sqlite3.Connection, case_ids: Iterable[int]) -> dict[int, dict[str, int]]:
    """一次查完这一页所有案例的上下文计数(避免 N+1)。"""
    ids = [int(value) for value in case_ids]
    if not ids:
        return {}
    placeholders = ", ".join("?" for _ in ids)
    rows = conn.execute(
        f"SELECT case_id, context_type, COUNT(*) AS total FROM vulnerability_case_context WHERE case_id IN ({placeholders}) GROUP BY case_id, context_type",
        ids,
    ).fetchall()
    counts: dict[int, dict[str, int]] = {value: {} for value in ids}
    for row in rows:
        counts[int(row["case_id"])][str(row["context_type"])] = int(row["total"])
    return counts


# ── 写:案例 ─────────────────────────────────────────────────────────────────

def upsert_case(
    conn: sqlite3.Connection,
    *,
    canonical_id: str = "",
    id_kind: str = "",
    actor: str = "",
    source: str = "",
    status: str = "",
    overwrite_manual: bool = False,
    context_rows: list[dict[str, Any]] | None = None,
    payload: dict[str, Any] | None = None,
    **fields: Any,
) -> dict[str, Any]:
    """按 canonical_id 幂等写入。返回 {case_id, created, updated, canonical_id, skipped_manual_fields}。

    合并规则(顺序即优先级):
      ① 人工案例(`source='manual_added'`)默认**只填空缺** —— 自动采集不得覆盖人写的元数据,
         除非显式 `overwrite_manual=True`(页面上的"用外部源刷新"按钮走这条路)。
      ② 数组列一律**取并集**(CVE/CWE/别名/受影响范围/引用/继承的素材 id),不做替换:
         重新富化只应增补,不该因为某次响应少给了一项就把已收集的上下文抹掉。
      ③ `modified_at` 取较大值(它是回溯富化的 watermark);`published_at` 只填空缺。
      ④ `status` 显式传入才改,且**已 superseded 的不被自动复活**(回滚/重跑不会把旧事件重新顶上来)。
    """
    normalized = normalize_canonical_id(canonical_id) if canonical_id else None
    if normalized:
        canonical_id = normalized["canonical_id"]
        id_kind = id_kind or normalized["id_kind"]
    canonical_id = str(canonical_id or "").strip()
    if not canonical_id:
        raise ValueError("canonical_id 不能为空")
    id_kind = str(id_kind or "custom")
    if id_kind not in ID_KINDS:
        raise ValueError(f"不支持的 id_kind: {id_kind}")
    if status and status not in CASE_STATUSES:
        raise ValueError(f"不支持的 status: {status}")

    incoming = {key: value for key, value in fields.items() if value is not None}
    unknown = set(incoming) - set(SCALAR_FIELDS) - set(ARRAY_FIELDS)
    if unknown:
        raise ValueError(f"不认识的案例字段: {sorted(unknown)}(要放自由信息请用 payload=)")
    existing_row = conn.execute("SELECT * FROM vulnerability_cases WHERE canonical_id = ?", (canonical_id,)).fetchone()
    now = utc_now()
    if existing_row is None:
        row_values: dict[str, Any] = {"canonical_id": canonical_id, "id_kind": id_kind, **incoming}
        row_values["status"] = status or ("pending_fetch" if id_kind in {"cve", "ghsa", "osv"} else "active")
        row_values["source"] = source
        row_values["created_by"] = actor
        row_values["created_at"] = now
        row_values["updated_by"] = actor
        row_values["updated_at"] = now
        for field in ARRAY_FIELDS:
            row_values[f"{field}_json"] = repo.dumps(incoming.get(field) or [])
        columns = ["canonical_id", "id_kind", "title", "summary", "severity", "cvss_score", "cvss_vector", "status", "source", "source_url", "published_at", "modified_at", "created_by", "created_at", "updated_by", "updated_at", *[f"{field}_json" for field in ARRAY_FIELDS]]
        # cvss_score 是 REAL 且**可空**(NULL = 未知):不能像文本列那样把 None 兜成空串 ——
        # 空串进 REAL 列会被原样存成 '' ,refresh_completeness 里"有没有分数"的判断就永远为真。
        values = [row_values.get(column) if column == "cvss_score" else (row_values.get(column) if row_values.get(column) is not None else "") for column in columns]
        # payload_json 是"自由附带信息"的家(调用方传的 payload + 非数组的标量字段),
        # 与下面 UPDATE 分支的口径保持一致:同一个案例无论新建还是更新,payload 结构不变。
        payload_doc = {**(payload or {}), **{key: value for key, value in incoming.items() if key not in ARRAY_FIELDS}}
        conn.execute(
            f"INSERT INTO vulnerability_cases ({', '.join(columns)}, payload_json) VALUES ({', '.join('?' for _ in columns)}, ?)",
            (*values, repo.dumps(payload_doc)),
        )
        case_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
        created = True
        skipped: list[str] = []
    else:
        existing = serialize_case(existing_row)
        manual_owned = str(existing.get("source") or "") == MANUAL_SOURCE and not overwrite_manual
        skipped = []
        updates: dict[str, Any] = {}
        for field in SCALAR_FIELDS:
            if field not in incoming:
                continue
            value = incoming[field]
            if value == "" or value is None:
                continue
            if manual_owned:
                # 人工案例:只填空缺
                if str(existing.get(field) or "") not in {"", "None"}:
                    skipped.append(field)
                    continue
                updates[field] = value
                continue
            if field == "modified_at":
                updates[field] = max(str(existing.get(field) or ""), str(value))
            elif field == "published_at":
                updates[field] = str(existing.get(field) or "") or str(value)
            elif field == "source":
                updates[field] = str(existing.get(field) or "") or str(value)
            else:
                updates[field] = value
        for field in ARRAY_FIELDS:
            if field not in incoming:
                continue
            merged = list(dict.fromkeys([*(existing.get(field) or []), *(incoming.get(field) or [])]))
            updates[f"{field}_json"] = repo.dumps(merged)
        if status and status != "superseded" and str(existing.get("status")) == "superseded":
            # 已取代的不自动复活:重跑采集不该把旧事件的记录重新顶成 active
            updates["status"] = "superseded"
            skipped.append("status")
        elif status:
            updates["status"] = status
        incoming_payload = {**(payload or {}), **{key: value for key, value in incoming.items() if key not in ARRAY_FIELDS}}
        if incoming_payload:
            updates["payload_json"] = repo.dumps({**(existing.get("payload") or {}), **incoming_payload})
        case_id = int(existing["id"])
        updates["updated_at"] = now
        updates["updated_by"] = actor
        assignments = ", ".join(f"{column} = ?" for column in updates)
        conn.execute(f"UPDATE vulnerability_cases SET {assignments} WHERE id = ?", (*updates.values(), case_id))
        created = False

    context_inserted = 0
    if context_rows:
        context_inserted = add_context(conn, case_id, context_rows, actor=actor, commit=False)
    refresh_completeness(conn, case_id, commit=False)
    conn.commit()
    return {"case_id": case_id, "canonical_id": canonical_id, "created": created, "updated": not created, "context_inserted": context_inserted, "skipped_manual_fields": skipped}


def update_case(conn: sqlite3.Connection, case_id: int, *, actor: str = "", **fields: Any) -> dict[str, Any]:
    """人工在页面上改字段(PATCH)。白名单外的键直接丢弃,不做"猜你想改什么"。"""
    row = conn.execute("SELECT id FROM vulnerability_cases WHERE id = ?", (int(case_id),)).fetchone()
    if row is None:
        raise ValueError("案例不存在")
    updates: dict[str, Any] = {}
    for field, value in fields.items():
        if field not in EDITABLE_FIELDS:
            continue
        if field in ARRAY_FIELDS:
            updates[f"{field}_json"] = repo.dumps(value if isinstance(value, list) else [])
        elif field == "status":
            if value not in CASE_STATUSES:
                raise ValueError(f"不支持的 status: {value}")
            updates[field] = value
        else:
            updates[field] = value
    if not updates:
        return {"case_id": int(case_id), "changed": 0}
    updates["updated_at"] = utc_now()
    updates["updated_by"] = actor
    assignments = ", ".join(f"{column} = ?" for column in updates)
    conn.execute(f"UPDATE vulnerability_cases SET {assignments} WHERE id = ?", (*updates.values(), int(case_id)))
    conn.commit()
    refresh_completeness(conn, int(case_id))
    return {"case_id": int(case_id), "changed": len(updates) - 2}


# ── 写:上下文 ───────────────────────────────────────────────────────────────

def add_context(conn: sqlite3.Connection, case_id: int, rows: list[dict[str, Any]], *, actor: str = "", commit: bool = True) -> int:
    """批量写入上下文行,返回**真正新增**的条数。

    幂等靠表上的 `UNIQUE(case_id, context_type, file_path, start_line, content_hash)` +
    `INSERT OR IGNORE` —— 采集/富化/重抽都会反复喂同一批行,靠应用层"先查后写"既慢又会漏并发。
    副作用是:人工改过的行不会被打架覆盖(规则 3),代价是同位置同内容的新版本写不进去
    (内容变了 hash 就变了,所以实际上只在"逐字节相同"时才被忽略,这是我们要的)。
    """
    if not rows:
        return 0
    existing = conn.execute("SELECT id FROM vulnerability_cases WHERE id = ?", (int(case_id),)).fetchone()
    if existing is None:
        raise ValueError("案例不存在")
    now = utc_now()
    inserted = 0
    for row in rows:
        context_type = str(row.get("context_type") or "")
        if context_type not in CONTEXT_TYPES:
            raise ValueError(f"不支持的 context_type: {context_type}")
        provenance = str(row.get("provenance") or "")
        if provenance not in PROVENANCES:
            raise ValueError(f"上下文必须带合法 provenance,收到: {provenance!r}")
        content = str(row.get("content") or "")
        confidence = row.get("confidence")
        if provenance in LLM_PROVENANCES and confidence is None:
            # 规则 2:模型说的话必须带自评置信度,否则前端无法与外部事实分层
            raise ValueError(f"provenance={provenance} 必须提供 confidence")
        content_hash = str(row.get("content_hash") or "") or _content_hash(row, content)
        cursor = conn.execute(
            "INSERT OR IGNORE INTO vulnerability_case_context "
            "(case_id, context_type, provenance, confidence, repo, commit_sha, file_path, function_name, start_line, end_line, "
            " content, content_hash, source_url, ref_item_id, label, order_index, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                int(case_id), context_type, provenance, confidence,
                str(row.get("repo") or ""), str(row.get("commit_sha") or ""), str(row.get("file_path") or ""), str(row.get("function_name") or ""),
                int(row.get("start_line") or 0), int(row.get("end_line") or 0),
                content, content_hash, str(row.get("source_url") or ""), int(row.get("ref_item_id") or 0),
                str(row.get("label") or ""), int(row.get("order_index") or 0), str(row.get("created_by") or actor), now,
            ),
        )
        inserted += max(cursor.rowcount, 0)
    refresh_completeness(conn, int(case_id), commit=False)
    if commit:
        conn.commit()
    return inserted


def _content_hash(row: dict[str, Any], content: str) -> str:
    """内容指纹。站内素材引用用 `item:<id>` 做种子 —— 同一条素材重复挂到同一个洞上必须只落一行,
    而它的 `content` 可能为空(正文不进这张表,抽屉里按 id 去读原素材)。

    2026-10-19:补上"既没有正文、也不是站内素材"的分支。P3 采集的外部引用行
    (`source_url` 有值、`content` 为空、`ref_item_id=0`)原先全部落到同一个空种子,
    UNIQUE 约束会把它们判成同一行 —— 一个洞挂 20 条 references,库里只剩 1 条,
    而且不报错。身份只能是 URL 本身。
    """
    if not content and row.get("ref_item_id"):
        seed = f"item:{int(row['ref_item_id'])}"
    elif not content:
        seed = f"url:{row.get('source_url') or ''}"
    else:
        seed = "\n".join([
            str(row.get("repo") or ""), str(row.get("commit_sha") or ""), str(row.get("file_path") or ""),
            str(row.get("start_line") or 0), content,
        ])
    return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]


def refresh_completeness(conn: sqlite3.Connection, case_id: int, *, commit: bool = True) -> dict[str, Any]:
    """重算"上下文收全了没有"的 4 个位。

    单点写入:所有改案例/改上下文的函数最后都调它,别的地方不要自己拼这几个字段
    (页面上的进度条就是靠它,飘了等于骗人)。批量历史重算见 legacy_event_migration.py --recompute。
    """
    row = conn.execute("SELECT * FROM vulnerability_cases WHERE id = ?", (int(case_id),)).fetchone()
    if row is None:
        raise ValueError("案例不存在")
    case = serialize_case(row)
    types = {str(item["context_type"]) for item in conn.execute("SELECT DISTINCT context_type FROM vulnerability_case_context WHERE case_id = ?", (int(case_id),)).fetchall()}
    # 元数据算"齐"的口径:有标题,且至少有一个可判断严重性的字段。不要求 CVE 必填 ——
    # oss:/manual: 这类案例本来就没有外部 id。
    metadata_complete = 1 if str(case.get("title") or "").strip() and (str(case.get("severity") or "").strip() or case.get("cvss_score") is not None) else 0
    has_patch = 1 if "patch_diff" in types else 0
    has_vuln_site = 1 if "vuln_site" in types else 0
    has_dataflow = 1 if "dataflow" in types else 0
    completeness = round((metadata_complete + has_patch + has_vuln_site + has_dataflow) / 4, 2)
    conn.execute(
        "UPDATE vulnerability_cases SET metadata_complete = ?, has_patch = ?, has_vuln_site = ?, has_dataflow = ?, context_completeness = ? WHERE id = ?",
        (metadata_complete, has_patch, has_vuln_site, has_dataflow, completeness, int(case_id)),
    )
    if commit:
        conn.commit()
    return {"case_id": int(case_id), "metadata_complete": metadata_complete, "has_patch": has_patch, "has_vuln_site": has_vuln_site, "has_dataflow": has_dataflow, "context_completeness": completeness}


# ── 读 ───────────────────────────────────────────────────────────────────────

def list_cases(
    conn: sqlite3.Connection,
    *,
    q: str = "",
    severity: str = "",
    id_kind: str = "",
    source: str = "",
    status: str = "",
    completeness: str = "",
    has: str = "",
    manual: bool = False,
    project_id: int = 0,
    curated: bool = False,
    published_from: str = "",
    published_to: str = "",
    created_since: str = "",
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """列表。**关键词下推 SQL 分页**(照 /materials 的服务端分页先例),不把全量拉回前端过滤。

    `completeness` 支持 `full`(4 位全有) / `partial`(有上下文但没齐) / `empty`(只有元数据) ——
    这是运营最常用的一个筛选:"哪些洞还没收全上下文"。
    `created_since` 给今日情报页圈"这批新登记了哪些洞"(窗口由 service._batch_window 给出)。
    """
    where: list[str] = []
    params: list[Any] = []
    if q:
        like = f"%{q.strip()}%"
        where.append("(canonical_id LIKE ? OR title LIKE ? OR summary LIKE ? OR cve_ids_json LIKE ? OR cwe_ids_json LIKE ?)")
        params.extend([like] * 5)
    for column, value in (("severity", severity), ("id_kind", id_kind), ("source", source), ("status", status)):
        if value:
            where.append(f"{column} = ?")
            params.append(value)
    if published_from:
        where.append("published_at >= ?")
        params.append(published_from)
    if published_to:
        where.append("published_at <= ?")
        params.append(published_to)
    if created_since:
        where.append("created_at >= ?")
        params.append(created_since)
    if project_id:
        # 子查询而不是 JOIN:一条案例可能因包和仓各挂一行 link,JOIN 会让它在列表里出现两次。
        where.append("id IN (SELECT case_id FROM vulnerability_case_projects WHERE project_id = ?)")
        params.append(int(project_id))
    if curated:
        # B 层(默认展示口径):有"故事"的洞才进 —— 有 OSV/GHSA 记录、有补丁、CVSS≥9、
        # 人工添加、或已被某个项目命中。A 层(NVD 索引)里那批只有元数据的洞默认不展示,
        # 但按 ID/关键词仍搜得到(不传 curated 就是全量)。阈值来自 P5-0 标定,写在这里可复查。
        where.append(
            "(has_patch = 1"
            " OR (cvss_score IS NOT NULL AND cvss_score >= 9.0)"
            f" OR {human_added_sql()}"
            " OR affected_products_json NOT IN ('[]', '')"
            " OR ghsa_ids_json NOT IN ('[]', '')"
            " OR fixed_versions_json NOT IN ('[]', '')"
            " OR id IN (SELECT case_id FROM vulnerability_case_projects))"
        )
    if completeness == "full":
        where.append("has_patch = 1 AND has_vuln_site = 1 AND has_dataflow = 1 AND metadata_complete = 1")
    elif completeness == "partial":
        where.append("(has_patch + has_vuln_site + has_dataflow) > 0 AND (has_patch + has_vuln_site + has_dataflow) < 3")
    elif completeness == "empty":
        where.append("has_patch = 0 AND has_vuln_site = 0 AND has_dataflow = 0")
    if has:
        # "有某一格"的正向筛选(2026-10-23): 页面上那 4 根进度条点一下就列出"有补丁的有哪些"。
        # 与 completeness 共用同一批列, 只是方向相反 —— 未知取值明确报错, 不静默当没传。
        predicate = HAS_PREDICATES.get(has)
        if not predicate:
            raise ValueError(f"Unsupported has: {has!r} (可选: {sorted(HAS_PREDICATES)})")
        where.append(predicate)
    if manual:
        # 页面上「人工添加」那个数字点下去走这里:既包含按 ID 自动抓的,也包含完全手填的。
        # 不能直接筛 source:自动抓的那批 source 是 manual_id,富化后还可能不是它。
        where.append(human_added_sql())
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    total = int(conn.execute(f"SELECT COUNT(*) FROM vulnerability_cases {clause}", params).fetchone()[0])
    rows = conn.execute(
        f"SELECT * FROM vulnerability_cases {clause} ORDER BY (published_at = '') ASC, published_at DESC, updated_at DESC, id DESC LIMIT ? OFFSET ?",
        (*params, max(1, min(int(limit), 200)), max(0, int(offset))),
    ).fetchall()
    counts = _case_counts(conn, [int(row["id"]) for row in rows])
    items = [serialize_case(row, counts.get(int(row["id"]), {})) for row in rows]
    return {"count": len(items), "total": total, "limit": int(limit), "offset": int(offset), "items": items}


def case_detail(conn: sqlite3.Connection, case_id: int) -> dict[str, Any] | None:
    """详情:案例本体 + 按 context_type 分组的上下文。代码片段只在这里出现(列表不带 content)。"""
    row = conn.execute("SELECT * FROM vulnerability_cases WHERE id = ?", (int(case_id),)).fetchone()
    if row is None:
        return None
    context_rows = conn.execute(
        "SELECT * FROM vulnerability_case_context WHERE case_id = ? ORDER BY context_type, order_index, id",
        (int(case_id),),
    ).fetchall()
    grouped: dict[str, list[dict[str, Any]]] = {context_type: [] for context_type in CONTEXT_TYPES}
    for context_row in context_rows:
        item = dict(context_row)
        item["is_manual"] = str(item.get("provenance") or "") == "manual_added"
        item["is_inference"] = str(item.get("provenance") or "") in LLM_PROVENANCES
        grouped.setdefault(str(item["context_type"]), []).append(item)
    counts = {context_type: len(items) for context_type, items in grouped.items() if items}
    case = serialize_case(row, counts)
    case["context"] = {context_type: items for context_type, items in grouped.items() if items}
    # 关联的站内素材:前端点它走既有的 openMaterialDrawer,所以这里只回 id/label/url 三件套。
    # provenance 一并带出去(P6a):`from_legacy_event` = 这条洞就是从这篇文章聚合出来的;
    # `from_material_cve` = 文章正文里出现过这个编号。两者都只说明"文章提到过",
    # 不说明"文章把这条案例讲透了",页面上按这个措辞展示。
    material_links = conn.execute(
        "SELECT ref_item_id AS item_id, MAX(provenance) AS provenance FROM vulnerability_case_context "
        "WHERE case_id = ? AND ref_item_id > 0 GROUP BY ref_item_id ORDER BY ref_item_id",
        (int(case_id),),
    ).fetchall()
    material_meta: dict[int, dict[str, Any]] = {}
    material_ids = [int(link["item_id"]) for link in material_links]
    if material_ids:
        placeholders = ",".join("?" for _ in material_ids)
        for material in conn.execute(
            "SELECT id, title, source_url FROM domain_items WHERE domain = 'vulnerabilities' "
            f"AND item_type = 'material' AND id IN ({placeholders})",
            material_ids,
        ):
            material_meta[int(material["id"])] = {"title": str(material["title"] or ""), "source_url": str(material["source_url"] or "")}
    case["materials"] = [
        {
            "item_id": int(link["item_id"]),
            # 素材已被清理时仍保留 id:页面显示"素材 #N",比静默消失诚实。
            "title": material_meta.get(int(link["item_id"]), {}).get("title", ""),
            "source_url": material_meta.get(int(link["item_id"]), {}).get("source_url", ""),
            "provenance": str(link["provenance"] or ""),
        }
        for link in material_links
    ]
    # P6a:这条案例的文章参与抽象过哪些模式(见 links.patterns_for_case 的口径说明)。
    # 局部 import:links 写回 reference 行时要用本模块的 add_context,模块级互相 import 会成环。
    from ai4sec_platform.domains.vulnerabilities.links import patterns_for_case

    case["patterns"] = patterns_for_case(conn, row)
    # 挂到哪些项目(P5a)。一条案例可能同时有 package_match / repo_match 两行,
    # 前端按项目去重展示,这里把两种证据都带上,让"为什么算这个项目的洞"可解释。
    project_rows = conn.execute(
        "SELECT p.id, p.slug, p.display_name, p.tier, l.link_kind, l.confidence "
        "FROM vulnerability_case_projects l JOIN vulnerability_projects p ON p.id = l.project_id "
        "WHERE l.case_id = ? ORDER BY p.display_name, l.link_kind",
        (int(case_id),),
    ).fetchall()
    case["projects"] = [
        {"id": int(item["id"]), "slug": item["slug"], "display_name": item["display_name"],
         "tier": item["tier"], "link_kind": item["link_kind"], "confidence": item["confidence"]}
        for item in project_rows
    ]
    return case


def case_stats(conn: sqlite3.Connection) -> dict[str, Any]:
    """案例库顶部那排数字 + 上下文完整度分布。领导那句"上下文收集全"在页面上就是这几个数。"""
    total = int(conn.execute("SELECT COUNT(*) FROM vulnerability_cases").fetchone()[0])
    def grouped(column: str) -> dict[str, int]:
        return {str(row[column] or ""): int(row["total"] or 0) for row in conn.execute(f"SELECT {column}, COUNT(*) AS total FROM vulnerability_cases GROUP BY {column}")}
    bits = conn.execute(
        "SELECT SUM(metadata_complete) AS metadata, SUM(has_patch) AS patch, SUM(has_vuln_site) AS vuln_site, SUM(has_dataflow) AS dataflow, "
        "SUM(CASE WHEN has_patch = 1 AND has_vuln_site = 1 AND has_dataflow = 1 AND metadata_complete = 1 THEN 1 ELSE 0 END) AS full, "
        "SUM(CASE WHEN has_patch = 0 AND has_vuln_site = 0 AND has_dataflow = 0 THEN 1 ELSE 0 END) AS empty FROM vulnerability_cases"
    ).fetchone()
    return {
        "total": total,
        "by_status": grouped("status"),
        "by_id_kind": grouped("id_kind"),
        "by_severity": grouped("severity"),
        # 与 list_cases(manual=True)、is_manual 同一判据:点开这个数字看到的条数必须等于它本身
        "manual": int(conn.execute(f"SELECT COUNT(*) FROM vulnerability_cases WHERE {human_added_sql()}").fetchone()[0]),
        "context": {
            "metadata": int(bits["metadata"] or 0),
            "patch": int(bits["patch"] or 0),
            "vuln_site": int(bits["vuln_site"] or 0),
            "dataflow": int(bits["dataflow"] or 0),
            "full": int(bits["full"] or 0),
            "empty": int(bits["empty"] or 0),
        },
        "context_rows": {
            str(row["context_type"]): int(row["total"] or 0)
            for row in conn.execute("SELECT context_type, COUNT(*) AS total FROM vulnerability_case_context GROUP BY context_type")
        },
    }


# ── 采集源(P3 消费) ─────────────────────────────────────────────────────────

def list_case_sources(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    return [dict(row) for row in conn.execute("SELECT * FROM vulnerability_case_sources ORDER BY kind, source_key, id")]


def add_case_source(conn: sqlite3.Connection, *, kind: str, identifier: str, source_key: str = "", label: str = "", note: str = "", created_by: str = "") -> dict[str, Any]:
    """登记一个要盯的源。重复添加 = 重新启用(与 threat_source_targets.add_target 行为一致)。"""
    kind = str(kind or "").strip()
    if kind not in {"tracked_package", "tracked_repo", "manual_id"}:
        raise ValueError(f"不支持的 kind: {kind}")
    identifier = str(identifier or "").strip()
    if not identifier:
        raise ValueError("identifier 不能为空")
    source_key = str(source_key or ("manual" if kind == "manual_id" else "osv")).strip()
    existing = conn.execute(
        "SELECT id, enabled FROM vulnerability_case_sources WHERE kind = ? AND source_key = ? AND identifier = ?",
        (kind, source_key, identifier),
    ).fetchone()
    if existing:
        if not bool(existing["enabled"]):
            conn.execute("UPDATE vulnerability_case_sources SET enabled = 1 WHERE id = ?", (int(existing["id"]),))
            conn.commit()
        row = conn.execute("SELECT * FROM vulnerability_case_sources WHERE id = ?", (int(existing["id"]),)).fetchone()
        return {"source": dict(row), "created": False}
    conn.execute(
        "INSERT INTO vulnerability_case_sources (kind, source_key, identifier, label, note, enabled, created_by, created_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
        (kind, source_key, identifier, str(label or "")[:120], str(note or ""), str(created_by or ""), utc_now()),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM vulnerability_case_sources WHERE id = last_insert_rowid()").fetchone()
    return {"source": dict(row), "created": True}


def set_case_source_enabled(conn: sqlite3.Connection, source_id: int, enabled: bool) -> dict[str, Any]:
    conn.execute("UPDATE vulnerability_case_sources SET enabled = ? WHERE id = ?", (1 if enabled else 0, int(source_id)))
    conn.commit()
    row = conn.execute("SELECT * FROM vulnerability_case_sources WHERE id = ?", (int(source_id),)).fetchone()
    if row is None:
        raise ValueError("采集源不存在")
    return dict(row)


def delete_case_source(conn: sqlite3.Connection, source_id: int) -> int:
    cursor = conn.execute("DELETE FROM vulnerability_case_sources WHERE id = ?", (int(source_id),))
    conn.commit()
    return max(cursor.rowcount, 0)
