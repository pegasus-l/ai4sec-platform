from __future__ import annotations

import json
import sqlite3
from typing import Any

from ai4sec_platform.core.time import utc_now


def dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False)


def loads(value: str | None, fallback: Any = None) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except Exception:
        return fallback


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    for key in ["tags_json", "metrics_json", "payload_json", "summary_json", "details_json", "payload_summary_json"]:
        if key in item:
            out_key = key.removesuffix("_json")
            item[out_key] = loads(item.pop(key), [] if key == "tags_json" else {})
    return item



def create_raw_artifact(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    domain: str,
    source: str,
    source_type: str = "",
    source_path: str = "",
    artifact_id: int | None = None,
    item_count: int = 0,
    payload: dict[str, Any] | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO raw_artifacts (run_id, domain, source, source_type, source_path, artifact_id, item_count, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, domain, source, source_type, source_path, artifact_id, item_count, dumps(payload or {}), utc_now()),
    )
    return int(cur.lastrowid)


def create_normalized_item(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    domain: str,
    item_key: str,
    source: str,
    source_type: str,
    title: str,
    url: str = "",
    primary_date: str = "",
    normalized: dict[str, Any] | None = None,
    raw_artifact_id: int | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO normalized_items (run_id, domain, item_key, source, source_type, title, url, primary_date, normalized_json, raw_artifact_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, domain, item_key, source, source_type, title, url, primary_date, dumps(normalized or {}), raw_artifact_id, utc_now()),
    )
    return int(cur.lastrowid)


def list_normalized_items(conn: sqlite3.Connection, *, run_id: str, domain: str = "news", limit: int = 1000) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM normalized_items WHERE run_id = ? AND domain = ? ORDER BY id LIMIT ?",
        (run_id, domain, limit),
    ).fetchall()
    return [row_to_dict(row) for row in rows]


def create_domain_item(
    conn: sqlite3.Connection,
    *,
    domain: str,
    item_type: str,
    title: str,
    summary: str = "",
    score: float | None = None,
    status: str = "active",
    source: str = "",
    source_url: str = "",
    primary_date: str = "",
    tags: list[str] | None = None,
    metrics: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
) -> int:
    now = utc_now()
    cur = conn.execute(
        """
        INSERT INTO domain_items (
            domain, item_type, title, summary, score, status, source, source_url,
            primary_date, tags_json, metrics_json, payload_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, item_type, title, summary, score, status, source, source_url, primary_date, dumps(tags or []), dumps(metrics or {}), dumps(payload or {}), now, now),
    )
    return int(cur.lastrowid)


def create_evidence(
    conn: sqlite3.Connection,
    *,
    domain: str,
    domain_item_id: int,
    evidence_type: str,
    title: str = "",
    content: str = "",
    source_url: str = "",
    confidence: float | None = None,
    payload: dict[str, Any] | None = None,
) -> int:
    cur = conn.execute(
        """
        INSERT INTO evidence_items (
            domain, domain_item_id, evidence_type, title, content,
            source_url, confidence, payload_json, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, domain_item_id, evidence_type, title, content, source_url, confidence, dumps(payload or {}), utc_now()),
    )
    return int(cur.lastrowid)


def create_pipeline_run(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    domain: str,
    pipeline_name: str,
    status: str = "success",
    started_at: str = "",
    finished_at: str = "",
    production_writes: bool = False,
    summary: dict[str, Any] | None = None,
    source_path: str = "",
) -> None:
    now = utc_now()
    existing = conn.execute("SELECT run_id, started_at, created_at FROM pipeline_runs WHERE run_id = ?", (run_id,)).fetchone()
    if existing:
        conn.execute(
            """
            UPDATE pipeline_runs
            SET domain = ?, pipeline_name = ?, status = ?, started_at = ?, finished_at = ?,
                production_writes = ?, summary_json = ?, source_path = ?
            WHERE run_id = ?
            """,
            (
                domain,
                pipeline_name,
                status,
                started_at or existing["started_at"] or now,
                finished_at,
                int(production_writes),
                dumps(summary or {}),
                source_path,
                run_id,
            ),
        )
        return
    conn.execute(
        """
        INSERT INTO pipeline_runs (
            run_id, domain, pipeline_name, status, started_at, finished_at,
            production_writes, summary_json, source_path, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, domain, pipeline_name, status, started_at or now, finished_at, int(production_writes), dumps(summary or {}), source_path, now),
    )


def create_task_run(conn: sqlite3.Connection, *, run_id: str, step_name: str, status: str = "success", metrics: dict[str, Any] | None = None, error_message: str = "") -> None:
    now = utc_now()
    conn.execute(
        """
        INSERT INTO task_runs (run_id, step_name, status, started_at, finished_at, metrics_json, error_message)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, step_name, status, now, now, dumps(metrics or {}), error_message),
    )


def create_artifact(conn: sqlite3.Connection, *, run_id: str, artifact_type: str, path: str, sha256: str = "", bytes_size: int = 0, payload_summary: dict[str, Any] | None = None) -> None:
    conn.execute(
        """
        INSERT INTO artifacts (run_id, artifact_type, path, sha256, bytes, payload_summary_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, artifact_type, path, sha256, bytes_size, dumps(payload_summary or {}), utc_now()),
    )


def create_data_source(conn: sqlite3.Connection, *, domain: str, name: str, source_type: str, status: str = "ok", latest_at: str = "", health: str = "ok", summary: dict[str, Any] | None = None) -> None:
    conn.execute(
        """
        INSERT INTO data_sources (domain, name, source_type, status, latest_at, health, summary_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, name, source_type, status, latest_at, health, dumps(summary or {}), utc_now()),
    )


def create_quality_audit(conn: sqlite3.Connection, *, domain: str, audit_type: str, status: str, score: float | None = None, summary: str = "", details: dict[str, Any] | None = None) -> None:
    conn.execute(
        """
        INSERT INTO quality_audits (domain, audit_type, status, score, summary, details_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, audit_type, status, score, summary, dumps(details or {}), utc_now()),
    )


def create_human_queue_item(conn: sqlite3.Connection, *, domain: str, item_id: int | None, queue_type: str, status: str = "pending", priority: int = 3, reason: str = "", assignee: str = "", payload: dict[str, Any] | None = None) -> None:
    now = utc_now()
    conn.execute(
        """
        INSERT INTO human_queue_items (domain, item_id, queue_type, status, priority, reason, assignee, payload_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (domain, item_id, queue_type, status, priority, reason, assignee, dumps(payload or {}), now, now),
    )



def create_model_call(
    conn: sqlite3.Connection,
    *,
    run_id: str,
    agent_name: str,
    model_profile: str,
    provider: str = "local_rules",
    status: str = "success",
    input_payload: dict[str, Any] | None = None,
    output_payload: dict[str, Any] | None = None,
    latency_ms: int = 0,
    error_message: str = "",
    task_run_id: str = "",
) -> int:
    cur = conn.execute(
        """
        INSERT INTO model_calls (run_id, task_run_id, agent_name, model_profile, provider, status, input_json, output_json, latency_ms, error_message, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (run_id, task_run_id, agent_name, model_profile, provider, status, dumps(input_payload or {}), dumps(output_payload or {}), latency_ms, error_message, utc_now()),
    )
    return int(cur.lastrowid)


def update_domain_item(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    status: str | None = None,
    score: float | None = None,
    metrics: dict[str, Any] | None = None,
    payload: dict[str, Any] | None = None,
    title: str | None = None,
    summary: str | None = None,
    source: str | None = None,
    source_url: str | None = None,
    primary_date: str | None = None,
    tags: list[str] | None = None,
) -> None:
    existing = conn.execute("SELECT metrics_json, payload_json FROM domain_items WHERE id = ?", (item_id,)).fetchone()
    if not existing:
        return
    current_metrics = loads(existing["metrics_json"], {})
    current_payload = loads(existing["payload_json"], {})
    if metrics:
        current_metrics.update(metrics)
    if payload:
        current_payload.update(payload)
    fields = ["metrics_json = ?", "payload_json = ?", "updated_at = ?"]
    params: list[Any] = [dumps(current_metrics), dumps(current_payload), utc_now()]
    if status is not None:
        fields.append("status = ?")
        params.append(status)
    if score is not None:
        fields.append("score = ?")
        params.append(score)
    if title is not None:
        fields.append("title = ?")
        params.append(title)
    if summary is not None:
        fields.append("summary = ?")
        params.append(summary)
    if source is not None:
        fields.append("source = ?")
        params.append(source)
    if source_url is not None:
        fields.append("source_url = ?")
        params.append(source_url)
    if primary_date is not None:
        fields.append("primary_date = ?")
        params.append(primary_date)
    if tags is not None:
        fields.append("tags_json = ?")
        params.append(dumps(tags))
    params.append(item_id)
    conn.execute(f"UPDATE domain_items SET {', '.join(fields)} WHERE id = ?", params)


def list_domain_items(conn: sqlite3.Connection, domain: str, *, item_type: str | None = None, limit: int = 50,
                      status: str | None = None, exclude_status: str | None = None, since: str | None = None,
                      offset: int = 0, forms: list[str] | None = None, repro_chips: list[str] | None = None,
                      q: str | None = None) -> list[dict[str, Any]]:
    """列 domain_items。

    offset 默认 0 → 不传时行为与改动前完全一致(其它域调用方零影响)。
    forms/repro_chips/q 见 build_item_filters: 给了就下推到 SQL, 不再把全量行拉进 Python 过滤。
    """
    where, params = _domain_items_where(domain, item_type=item_type, status=status,
                                        exclude_status=exclude_status, since=since,
                                        forms=forms, repro_chips=repro_chips, q=q)
    sql = ("SELECT * FROM domain_items" + where
           + " ORDER BY COALESCE(score, 0) DESC, primary_date DESC, id DESC LIMIT ? OFFSET ?")
    params.extend([limit, offset])
    return [row_to_dict(row) for row in conn.execute(sql, params).fetchall()]


def count_domain_items(conn: sqlite3.Connection, domain: str, *, item_type: str | None = None,
                       status: str | None = None, exclude_status: str | None = None, since: str | None = None,
                       forms: list[str] | None = None, repro_chips: list[str] | None = None,
                       q: str | None = None) -> int:
    """数命中条数(与 list_domain_items 同判据), 供分页返回精确 total。"""
    where, params = _domain_items_where(domain, item_type=item_type, status=status,
                                        exclude_status=exclude_status, since=since,
                                        forms=forms, repro_chips=repro_chips, q=q)
    return int(conn.execute("SELECT COUNT(*) FROM domain_items" + where, params).fetchone()[0])


def classify_stats_by_domain(conn: sqlite3.Connection, domain: str) -> dict[str, Any]:
    """Web 分类进度统计: 一条 SQL 聚合。

    2026-09-15 改写: 原实现(app/api/capabilities.py)list_domain_items(limit=10000) 把全量行
    连完整 payload 拉进 Python 只为数 4 个整数(实测 0.378s, 响应仅 75 字节)。判据与原 Python
    逐条对齐(已在生产库比对过四个数字):
      in_repo    = code_url 非空 或 source_url 含 'github.com'; 用 instr 保持大小写敏感
                   (LIKE 对 ASCII 不区分大小写, 会把 'GitHub.com' 也算进来, 与原逻辑不符)
      classified = in_repo 且 web_classify_ts 为真(非 NULL/''/0)
      web_count  = in_repo 且 is_web 为真
    """
    in_repo = ("(COALESCE(json_extract(payload_json, '$.code_url'), '') != ''"
               " OR instr(COALESCE(source_url, ''), 'github.com') > 0)")
    classify_ts = ("(json_extract(payload_json, '$.web_classify_ts') IS NOT NULL"
                   " AND json_extract(payload_json, '$.web_classify_ts') != ''"
                   " AND json_extract(payload_json, '$.web_classify_ts') != 0)")
    row = conn.execute(
        f"""
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN {classify_ts} THEN 1 ELSE 0 END) AS classified,
            SUM(CASE WHEN {_IS_WEB} THEN 1 ELSE 0 END) AS web_count
        FROM domain_items
        WHERE domain = ? AND status != ? AND {in_repo}
        """,
        (domain, "已淘汰"),
    ).fetchone()
    total = int(row["total"] or 0)
    classified = int(row["classified"] or 0)
    return {
        "total": total,
        "classified": classified,
        "unclassified": total - classified,
        "web_count": int(row["web_count"] or 0),
    }


def get_domain_item_by_repo(conn: sqlite3.Connection, domain: str, repo_url: str) -> dict[str, Any] | None:
    """按规范化仓库 URL(code_url)查 domain_item,同仓库取最高分一条。用于库级去重。"""
    row = conn.execute(
        "SELECT * FROM domain_items WHERE domain = ? AND json_extract(payload_json, '$.code_url') = ? "
        "ORDER BY COALESCE(score, 0) DESC, id DESC LIMIT 1",
        (domain, repo_url),
    ).fetchone()
    return row_to_dict(row) if row else None


def get_domain_item(conn: sqlite3.Connection, domain: str, item_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM domain_items WHERE domain = ? AND id = ?", (domain, item_id)).fetchone()
    if not row:
        return None
    item = row_to_dict(row)
    item["evidence"] = list_evidence(conn, domain, item_id)
    return item


def list_evidence(conn: sqlite3.Connection, domain: str, item_id: int) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM evidence_items WHERE domain = ? AND domain_item_id = ? ORDER BY id", (domain, item_id)).fetchall()
    return [row_to_dict(row) for row in rows]


# ============================================================================
# threat_links - 威胁分析 资产↔代码仓 关联边(幂等 upsert + join 列表)
# ============================================================================


def upsert_threat_link(
    conn: sqlite3.Connection,
    *,
    asset_id: int,
    repo_id: int,
    confidence: str = "inferred",
    reason: str = "",
    rel_type: str = "related",
    method: str = "llm",
    human_status: str = "none",
) -> None:
    """按 (asset_id, repo_id, method) 幂等 upsert 一条关联边。LLM 重跑只覆写同名行,保留人工状态。"""
    now = utc_now()
    row = conn.execute(
        "SELECT id FROM threat_links WHERE asset_id = ? AND repo_id = ? AND method = ?",
        (asset_id, repo_id, method),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE threat_links SET rel_type = ?, confidence = ?, reason = ?, human_status = ?, updated_at = ? WHERE id = ?",
            (rel_type, confidence, reason, human_status, now, row["id"]),
        )
    else:
        conn.execute(
            "INSERT INTO threat_links (asset_id, repo_id, rel_type, confidence, method, reason, human_status, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (asset_id, repo_id, rel_type, confidence, method, reason, human_status, now, now),
        )


def list_threat_links(conn: sqlite3.Connection, *, domain: str = "threats") -> list[dict[str, Any]]:
    """列出全部关联边,并 join 出资产与仓库侧元数据(标题/source/score/payload 已解析)。

    供 /associations bundle 一次性渲染;repo 侧元数据(grade/cve)由调用方从 repo_payload 取。
    """
    rows = conn.execute(
        """
        SELECT l.id AS link_id, l.asset_id, l.repo_id, l.rel_type, l.confidence, l.method,
               l.reason, l.human_status, l.created_at, l.updated_at,
               a.title AS asset_title, a.source AS asset_source, a.score AS asset_score,
               a.payload_json AS asset_payload_json,
               r.title AS repo_title, r.score AS repo_score, r.payload_json AS repo_payload_json
        FROM threat_links l
        JOIN domain_items a ON a.id = l.asset_id AND a.domain = ? AND a.item_type = 'asset'
        JOIN domain_items r ON r.id = l.repo_id AND r.domain = ? AND r.item_type = 'target'
        ORDER BY COALESCE(r.score, 0) DESC, l.id
        """,
        (domain, domain),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        d = row_to_dict(row)
        d["asset_payload"] = loads(d.pop("asset_payload_json", None), {})
        d["repo_payload"] = loads(d.pop("repo_payload_json", None), {})
        out.append(d)
    return out


def list_table(conn: sqlite3.Connection, table: str, *, domain: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    allowed = {"pipeline_runs", "task_runs", "artifacts", "data_sources", "quality_audits", "human_queue_items", "raw_artifacts", "normalized_items", "model_calls", "capability_repro_tasks"}
    if table not in allowed:
        raise ValueError(f"Unsupported table: {table}")
    if domain and table in {"pipeline_runs", "data_sources", "quality_audits", "human_queue_items"}:
        rows = conn.execute(f"SELECT * FROM {table} WHERE domain = ? ORDER BY id DESC LIMIT ?", (domain, limit)).fetchall()
    else:
        rows = conn.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    return [row_to_dict(row) for row in rows]


def count_by_domain(conn: sqlite3.Connection, domain: str) -> int:
    row = conn.execute("SELECT COUNT(*) AS count FROM domain_items WHERE domain = ?", (domain,)).fetchone()
    return int(row["count"])


# ============================================================================
# 能力卡筛选谓词(唯一真源, 2026-09-15)
# ============================================================================
# 「芯片上的数字」(/items/stats 的桶计数)与「列表里的内容」(/items?form=&repro=)必须同判据,
# 否则会出现「芯片写 1698 条、点进去却不是」这种自相矛盾。历史上前端还各有一份 Python 判据
# (CapabilityPage.tsx 的 matchesReproChip)靠人工对齐 —— 这里收敛成一批 SQL 片段:
# filter_stats_by_domain 用 SUM(CASE WHEN 片段) 计数, build_item_filters 用同一片段做 WHERE。
# 改口径时只改这一处, 计数与列表会一起变。
#
# 参数名与 /items/stats 响应里的键一一对应(web/non_web/demo/success/partial/in_progress/
# pending/failed/not_supported), 前端拿 stats 的键就能直接拼筛选参数。
_IS_WEB = "json_extract(payload_json, '$.is_web') IN (1, 'true', '1')"
_NO_DEMO = "COALESCE(json_extract(payload_json, '$.demo_url'), '') = ''"
_HAS_DEMO = "COALESCE(json_extract(payload_json, '$.demo_url'), '') != ''"
_REPRO_STATUS = "json_extract(payload_json, '$.repro_status')"

# 形态。非 Web 必须写成 NOT COALESCE(..., 0): is_web 缺失时 `json_extract(...) IN (...)` 求值为
# NULL, 直接 NOT 还是 NULL, WHERE 会把这些行整批丢掉 —— 而 stats 里 non_web = total - web 是把
# 它们算作非 Web 的, 两边会当场对不上(库内目前 is_web 全有值, 但新采集的行不保证)。
FORM_PREDICATES: dict[str, str] = {
    "web": _IS_WEB,
    "non_web": f"NOT COALESCE({_IS_WEB}, 0)",
}

# 可体验·复现。除 demo 外一律前置「无 demo + is_web 为真」: demo 是独立维度、不算复现结论;
# 非 web 条目不参与复现维度(已被 web 把关挡在复现队列外, 不该在任何复现桶里冒充"待复现")。
REPRO_PREDICATES: dict[str, str] = {
    "demo": _HAS_DEMO,
    "success": f"{_NO_DEMO} AND {_IS_WEB} AND {_REPRO_STATUS} IN ('success', 'succeeded')",
    "partial": f"{_NO_DEMO} AND {_IS_WEB} AND {_REPRO_STATUS} = 'partial'",
    "in_progress": f"{_NO_DEMO} AND {_IS_WEB} AND {_REPRO_STATUS} = 'in_progress'",
    "pending": f"{_NO_DEMO} AND {_IS_WEB} AND ({_REPRO_STATUS} IN ('candidate', 'no_code') OR {_REPRO_STATUS} IS NULL)",
    "failed": f"{_NO_DEMO} AND {_IS_WEB} AND {_REPRO_STATUS} IN ('failed', 'error')",
    "not_supported": f"{_NO_DEMO} AND {_IS_WEB} AND {_REPRO_STATUS} = 'not_supported'",
}
REPRO_KEYS: tuple[str, ...] = ("success", "partial", "in_progress", "pending", "failed", "not_supported")

# 能力卡搜索覆盖的 payload 展示键(services/domain_items._item_matches_q 也引用这一份, 避免两处清单漂移)
CAP_SEARCH_PAYLOAD_KEYS: tuple[str, ...] = (
    "display_title", "display_work_name", "display_topic", "one_liner", "overview",
    "summary", "code_url",
)
_CAP_SEARCH_COLUMNS: tuple[str, ...] = ("title", "summary", "source_url")

# 反斜杠: LIKE ... ESCAPE 用的转义字符。写成 chr(92) 而不是字面量, 免得源码里的反斜杠
# 转义层级看错(看错一次用户搜 "50%" 就会变成通配符全表命中)。
_LIKE_ESC = chr(92)


def _like_escape(q: str) -> str:
    """把关键词包成 LIKE 模式串, 并转义 % / _ / 反斜杠本身。"""
    e = _LIKE_ESC
    return "%" + q.replace(e, e + e).replace("%", e + "%").replace("_", e + "_") + "%"


def cap_haystack_sql() -> str:
    """拼接式搜索 haystack, 与 services/domain_items._item_matches_q 的 `" ".join(parts)` 同构。

    为什么不能逐列 LIKE: Python 先把各字段拼成长串再找子串, 所以"标题末词 + 摘要首词"这类
    跨字段组合能命中; 逐列 LIKE 只能命中落在单一字段内的词 —— 实测同一批真实构造的跨字段查询,
    逐列版会漏(改拼接版后与 Python 逐条一致)。
    拼接细节逐字对齐 Python:
      · 三个列(title/summary/source_url)无条件入列 —— 空值也会贡献一个分隔符;
      · 7 个 payload 展示键仅在非空时入列(`if val:`), 所以用 CASE 只在非空时补前导空格;
      · tech_points 是 list 时无条件 group_concat 入列, 非 list 且非空时才入列。
    LIKE 对 ASCII 默认不区分大小写, 与 Python 两侧 .lower() 等价(中文无大小写)。
    """
    parts = [" || ' ' || ".join(f"COALESCE({c}, '')" for c in _CAP_SEARCH_COLUMNS)]
    for k in CAP_SEARCH_PAYLOAD_KEYS:
        v = f"json_extract(payload_json, '$.{k}')"
        parts.append(f"CASE WHEN COALESCE({v}, '') != '' THEN ' ' || {v} ELSE '' END")
    tp = "json_extract(domain_items.payload_json, '$.tech_points')"
    gc = ("(SELECT group_concat(value, ' ') FROM (SELECT value FROM "
          "json_each(domain_items.payload_json, '$.tech_points') ORDER BY key))")
    parts.append(
        f"CASE WHEN json_type(domain_items.payload_json, '$.tech_points') = 'array'"
        f" THEN ' ' || COALESCE({gc}, '')"
        f" WHEN COALESCE({tp}, '') != '' THEN ' ' || {tp}"
        f" ELSE '' END"
    )
    return "(" + " || ".join(parts) + ")"


def search_predicate(q: str) -> tuple[str, list[Any]]:
    """能力卡搜索的 SQL 谓词, 与 _item_matches_q 等价(2026-09-15 实测含跨字段查询逐条一致)。"""
    return f"({cap_haystack_sql()} LIKE ? ESCAPE '{_LIKE_ESC}')", [_like_escape(q)]


def build_item_filters(*, forms: list[str] | None = None, repro_chips: list[str] | None = None,
                       q: str | None = None) -> tuple[str, list[Any]]:
    """把前端芯片与搜索词翻成 SQL 条件, 返回 (" AND (...)", params); 无条件时返回 ("", [])。

    形态语义与前端一致: 恰选一个才过滤(两个都不选/都选 = 全部)。复现芯片多选为 OR。
    非 Web 与复现芯片同时给出会得到空集 —— 前端不会有这种组合(只看非 Web 时复现芯片整排失效
    并清空), 真给出时返回空集也是诚实答案。
    """
    conds: list[str] = []
    params: list[Any] = []
    picked = [f for f in (forms or []) if f in FORM_PREDICATES]
    if len(picked) == 1:
        conds.append(f"({FORM_PREDICATES[picked[0]]})")
    chips = [c for c in (repro_chips or []) if c in REPRO_PREDICATES]
    if chips:
        conds.append("(" + " OR ".join(f"({REPRO_PREDICATES[c]})" for c in chips) + ")")
    q = (q or "").strip()
    if q:
        frag, fparams = search_predicate(q)
        conds.append(frag)
        params.extend(fparams)
    if not conds:
        return "", []
    return " AND " + " AND ".join(conds), params


def _domain_items_where(domain: str, *, item_type: str | None = None, status: str | None = None,
                        exclude_status: str | None = None, since: str | None = None,
                        forms: list[str] | None = None, repro_chips: list[str] | None = None,
                        q: str | None = None) -> tuple[str, list[Any]]:
    """组装 domain_items 的 WHERE(list_domain_items 与 count_domain_items 共用,
    保证「取这一页」与「数总数」判据完全一致 —— 否则 total 与页内容会对不上)。"""
    sql = " WHERE domain = ?"
    params: list[Any] = [domain]
    if item_type:
        sql += " AND item_type = ?"
        params.append(item_type)
    if status:
        sql += " AND status = ?"
        params.append(status)
    if exclude_status:
        sql += " AND status != ?"
        params.append(exclude_status)
    if since:
        # 时间下界(ISO-8601 UTC 字符串比较, 与 created_at 存储格式一致)
        sql += " AND created_at >= ?"
        params.append(since)
    frag, fparams = build_item_filters(forms=forms, repro_chips=repro_chips, q=q)
    sql += frag
    params.extend(fparams)
    return sql, params


def filter_stats_by_domain(conn: sqlite3.Connection, domain: str) -> dict[str, Any]:
    """能力库筛选统计:全量 SQL 聚合,不受 /items 的 limit 窗口影响。

    与 /items 列表同人口(domain + status != '已淘汰'),保证 chip 计数与列表一致。
    桶划分与前端 engineeringGroups 一致:官方 Demo 为独立维度(demo_url 有即归它),
    repro 桶全部前置「无 demo + is_web 为真」条件(非 web 不参与复现维度, 见下方 SQL 注释),各桶互斥;
    非 web 条目不落在任何 repro 桶里, 由前端「非 Web(不参与复现)」组承载。
    json_extract 对缺失键/非法 JSON 返回 NULL → 落入"不匹配"桶(非 Web / 待复现),
    与 Python 端 loads(payload_json, {}) 兜底语义一致。is_web 兼容 JSON true(=1) 与字符串 "true"/"1"。
    """
    _r = REPRO_PREDICATES
    _repro_sums = ",\n            ".join(
        "SUM(CASE WHEN %s THEN 1 ELSE 0 END) AS repro_%s" % (_r[k], k) for k in REPRO_KEYS
    )
    row = conn.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN %s THEN 1 ELSE 0 END) AS web_count,
            SUM(CASE WHEN %s THEN 1 ELSE 0 END) AS demo_count,
            -- 桶谓词集中在 REPRO_PREDICATES(唯一真源): 列表筛选(build_item_filters)复用同一批
            -- 片段, 所以「芯片上的数字」与「列表里的条数」结构性同源, 不会再各算一套(2026-09-15)。
            -- repro 各桶一律前置 is_web 为真: 非 web 条目已被 web 把关挡在复现队列外,
            -- 不该在任何复现桶里冒充"待复现"(实测旧口径 2029 条"待复现"里 1696 条是非 web)。
            -- 「官方 Demo」是独立维度, 不算复现结论, 故不设此门槛。
            %s
        FROM domain_items
        WHERE domain = ? AND status != ?
        """ % (_IS_WEB, _r["demo"], _repro_sums),
        (domain, "已淘汰"),
    ).fetchone()
    r = dict(row)
    total = int(r["total"] or 0)
    web = int(r["web_count"] or 0)
    return {
        "domain": domain,
        "total": total,
        "web": web,
        "non_web": total - web,  # 与 Python `not is_web` 语义一致(NULL → 非 Web)
        "demo": int(r["demo_count"] or 0),
        "repro": {
            "success": int(r["repro_success"] or 0),
            "partial": int(r["repro_partial"] or 0),
            "in_progress": int(r["repro_in_progress"] or 0),
            "pending": int(r["repro_pending"] or 0),
            "failed": int(r["repro_failed"] or 0),
            "not_supported": int(r["repro_not_supported"] or 0),
        },
    }


# ============================================================================
# capability_repro_tasks - 复现任务 CRUD（迁移自旧 v1 db.py）
# ============================================================================

_REPRO_UPDATABLE_FIELDS = {
    "status",
    "container_name",
    "workspace_path",
    "log",
    "result",
    "finished_at",
    "cleaned_at",
    "trigger",
    "report_json",
    "web_port",
    "web_url",
}


def create_repro_task(
    conn: sqlite3.Connection,
    *,
    item_id: int,
    repo_url: str,
    trigger: str = "manual",
) -> int:
    """创建复现任务，返回 task_id"""
    cur = conn.execute(
        "INSERT INTO capability_repro_tasks (item_id, repo_url, status, created_at, trigger) "
        "VALUES (?, ?, 'queued', ?, ?)",
        (item_id, repo_url, utc_now(), trigger),
    )
    return int(cur.lastrowid)


def get_repro_task(conn: sqlite3.Connection, task_id: int) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM capability_repro_tasks WHERE id = ?", (task_id,)).fetchone()
    if not row:
        return None
    item = dict(row)
    # report_json → report（保持 _json 后缀的字段也保留，方便 row_to_dict 调用方）
    return item


def list_repro_tasks(
    conn: sqlite3.Connection,
    *,
    item_id: int | None = None,
    limit: int = 200,
    include_cleaned: bool = False,
) -> list[dict[str, Any]]:
    """列出复现任务，可按 item_id 过滤；默认排除 cleaned"""
    if item_id is not None:
        sql = "SELECT * FROM capability_repro_tasks WHERE item_id = ?"
        params: list[Any] = [item_id]
        if not include_cleaned:
            sql += " AND status != 'cleaned'"
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
    else:
        sql = "SELECT * FROM capability_repro_tasks"
        params = []
        if not include_cleaned:
            sql += " WHERE status != 'cleaned'"
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


def update_repro_task(conn: sqlite3.Connection, *, task_id: int, **fields: Any) -> None:
    """更新复现任务字段，只允许白名单内字段"""
    sets, vals = [], []
    for k, v in fields.items():
        if k in _REPRO_UPDATABLE_FIELDS:
            sets.append(f"{k} = ?")
            vals.append(v)
    if not sets:
        return
    vals.append(task_id)
    conn.execute(f"UPDATE capability_repro_tasks SET {', '.join(sets)} WHERE id = ?", vals)


def append_repro_log(conn: sqlite3.Connection, *, task_id: int, line: str) -> None:
    """追加日志行到 task 的 log 字段（累积）"""
    conn.execute(
        "UPDATE capability_repro_tasks SET log = log || ? WHERE id = ?",
        (line + "\n", task_id),
    )


def get_succeeded_repro_item_ids(conn: sqlite3.Connection) -> set[int]:
    """已完整成功复现的 item_id 集合；partial 仍允许后续自动重试。"""
    rows = conn.execute(
        "SELECT DISTINCT item_id FROM capability_repro_tasks WHERE status = 'success'"
    ).fetchall()
    return {row["item_id"] for row in rows}


def get_active_repro_item_ids(conn: sqlite3.Connection) -> set[int]:
    """正在复现中的 item_id 集合"""
    rows = conn.execute(
        "SELECT DISTINCT item_id FROM capability_repro_tasks WHERE status IN ('queued', 'running')"
    ).fetchall()
    return {row["item_id"] for row in rows}

