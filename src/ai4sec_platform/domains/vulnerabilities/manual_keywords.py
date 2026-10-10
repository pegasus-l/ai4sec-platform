"""人工添加的漏洞检索关键词(2026-10-10)。

**为什么要这个模块**:漏洞域此前**没有任何写入口** —— 想加检索词只能手改
`configs/vulnerability_keywords.yaml` 再重启容器,而那个 YAML 是 Dockerfile `COPY configs`
烘进镜像的,`compose recreate` 就丢;页面上也无从查看当前到底在搜什么词。这里把人工词落库
(表 `vulnerability_manual_keywords`),由两条采集路径在解析完 keyword profile 之后合并。

**为什么合并在 `resolve_keyword_profile` 外面**:那个函数末尾会做
`queries[:effective_limit]` 截断(effective_limit = min(requested, profile_limit, 50))。
人工词一旦走进去,排在尾部就会被无声砍掉;而为了让位给人工词去砍轮换词,又会让
`rotation_selected_count` 变小,采集路径正是据此推进游标
(`advance_keyword_rotation_state`)→ **游标超前推进、跳过没搜过的词**。这是最隐蔽的一种
回归。所以合并放在函数**外面**:人工词前置,profile 自己的 ≤50 条一条不少,总查询数 =
len(人工) + profile 的条数。

**人工词不参与截断**,靠写入口的上限兜底:单个 profile 最多 `_MAX_PER_PROFILE` 条,超了
在 API 层直接 400 给用户看。跑批侧永不静默丢词 —— 排在末尾被下游上限吃掉的人工项,
页面上却还显示"已启用",是 2026-10-09 在威胁域踩过的坑
(见 pipelines/steps/threat_sources.py 的 merge_manual_targets 注释)。

**约定**:
- `profile_name` 指向 `configs/vulnerability_keywords.yaml` 里的 profile;特殊值 `*`
  表示"所有 profile 都带上"(见 `WILDCARD_PROFILE`)。profile 名可以为空串的调用方
  (采集路径里没传 keyword_profile 的子任务)会**整个跳过合并**,行为与改动前逐字一致。
- 停用(`enabled=0`)只是软关:行还在,页面上显示为删除线,再 add 一次同名词会把它重新
  启用而不是插一条重复的(与 domains/threats/source_registry.add_target 同一套约定)。
- 表由 db/models 的 SCHEMA_SQL 建(每次 get_db 都会跑),本模块的 `ensure_table` 是
  同源双写,防止在没走过 init_db 的连接上(单测、脚本)INSERT 失败。
"""
from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.db import repositories as repo

# 单个 profile 最多能存多少条人工词。写入口校验,不做截断。
MAX_PER_PROFILE = 20
# 单条关键词长度上限
MAX_KEYWORD_LENGTH = 160
# 单条备注长度上限
MAX_NOTE_LENGTH = 400
# 挂在某个 profile 上
_PROFILE_NAME_MAX = 64
# 特殊 profile:表示"所有 profile 都带上这个词"
WILDCARD_PROFILE = "*"


def ensure_table(conn: sqlite3.Connection) -> None:
    """建 vulnerability_manual_keywords(与 db/models 的 SCHEMA_SQL 同源,重复执行安全)。"""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS vulnerability_manual_keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            profile_name TEXT NOT NULL,
            keyword TEXT NOT NULL COLLATE NOCASE,
            label TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_by TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(profile_name, keyword)
        );
        CREATE INDEX IF NOT EXISTS idx_vulnerability_manual_keywords_profile
            ON vulnerability_manual_keywords(profile_name, enabled);
        """
    )
    conn.commit()


def table_ready(conn: sqlite3.Connection) -> bool:
    try:
        return bool(
            conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerability_manual_keywords'"
            ).fetchone()
        )
    except sqlite3.Error:
        return False


def _row_to_keyword(row: sqlite3.Row | tuple) -> dict[str, Any]:
    def get(key: str, index: int) -> Any:
        try:
            return row[key]
        except (TypeError, IndexError, KeyError):
            return row[index]

    return {
        "id": int(get("id", 0)),
        "profile_name": str(get("profile_name", 1) or ""),
        "keyword": str(get("keyword", 2) or ""),
        "label": str(get("label", 3) or ""),
        "note": str(get("note", 4) or ""),
        "enabled": bool(get("enabled", 5)),
        "created_by": str(get("created_by", 6) or ""),
        "created_at": str(get("created_at", 7) or ""),
    }


_SELECT_COLUMNS = "SELECT id, profile_name, keyword, label, note, enabled, created_by, created_at FROM vulnerability_manual_keywords"


def list_keywords(conn: sqlite3.Connection, *, profile_name: str | None = None) -> list[dict[str, Any]]:
    """列出人工关键词(停用的也返回 —— 页面要显示为删除线,供用户重新启用)。"""
    if not table_ready(conn):
        return []
    if profile_name is None:
        rows = conn.execute(f"{_SELECT_COLUMNS} ORDER BY id").fetchall()
    else:
        rows = conn.execute(f"{_SELECT_COLUMNS} WHERE profile_name = ? ORDER BY id", (profile_name,)).fetchall()
    return [_row_to_keyword(row) for row in rows]


def count_by_profile(conn: sqlite3.Connection) -> dict[str, int]:
    """每个 profile 已存的人工词条数(给 GET /keyword-profiles 顺带显示,省一次请求)。"""
    if not table_ready(conn):
        return {}
    rows = conn.execute(
        "SELECT profile_name, COUNT(*) FROM vulnerability_manual_keywords GROUP BY profile_name"
    ).fetchall()
    return {str(row[0] or ""): int(row[1]) for row in rows}


def _fetch_keyword(conn: sqlite3.Connection, keyword_id: int) -> dict[str, Any]:
    row = conn.execute(f"{_SELECT_COLUMNS} WHERE id=?", (keyword_id,)).fetchone()
    if row is None:
        raise ValueError("记录不存在")
    return _row_to_keyword(row)


# ---------------------------------------------------------------- 写操作


def _clean_keyword(value: str) -> str:
    return " ".join(str(value or "").split())


def add_keyword(
    conn: sqlite3.Connection,
    *,
    profile_name: str,
    keyword: str,
    label: str = "",
    note: str = "",
    created_by: str = "",
) -> dict[str, Any]:
    """人工添加检索关键词。返回 {keyword, created};重复添加视为幂等(把停用的重新启用)。"""
    profile = str(profile_name or "").strip()
    if not profile:
        raise ValueError("请选择要挂到哪个关键词配置(profile)")
    if len(profile) > _PROFILE_NAME_MAX:
        raise ValueError("profile 名不合法")
    clean = _clean_keyword(keyword)
    if not clean:
        raise ValueError("关键词不能为空")
    if len(clean) > MAX_KEYWORD_LENGTH:
        raise ValueError(f"关键词过长(不超过 {MAX_KEYWORD_LENGTH} 字符)")
    ensure_table(conn)
    total = conn.execute(
        "SELECT COUNT(*) FROM vulnerability_manual_keywords WHERE profile_name=?", (profile,)
    ).fetchone()[0]
    existing = conn.execute(
        "SELECT id, enabled FROM vulnerability_manual_keywords WHERE profile_name=? AND keyword=?",
        (profile, clean),
    ).fetchone()
    if existing:
        keyword_id, enabled = int(existing[0]), bool(existing[1])
        if not enabled:
            # 之前停用过,再添一次就当启用(而不是插一条重复的)
            conn.execute("UPDATE vulnerability_manual_keywords SET enabled=1 WHERE id=?", (keyword_id,))
            conn.commit()
        return {"keyword": _fetch_keyword(conn, keyword_id), "created": False}
    # 只在"新增"这条路径上卡上限:重复添加一条已停用的词不该被上限挡住。
    if int(total) >= MAX_PER_PROFILE:
        raise ValueError(f"该配置已有 {int(total)} 条人工关键词(上限 {MAX_PER_PROFILE}),请先删除不再需要的")
    conn.execute(
        "INSERT INTO vulnerability_manual_keywords "
        "(profile_name, keyword, label, note, enabled, created_by, created_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (
            profile,
            clean,
            str(label or "").strip()[:120],
            str(note or "").strip()[:MAX_NOTE_LENGTH],
            str(created_by or ""),
            repo.utc_now(),
        ),
    )
    conn.commit()
    keyword_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])
    return {"keyword": _fetch_keyword(conn, keyword_id), "created": True}


def set_keyword_enabled(conn: sqlite3.Connection, keyword_id: int, enabled: bool) -> dict[str, Any]:
    if not table_ready(conn):
        raise ValueError("记录不存在")
    row = conn.execute("SELECT id FROM vulnerability_manual_keywords WHERE id=?", (keyword_id,)).fetchone()
    if row is None:
        raise ValueError("记录不存在")
    conn.execute(
        "UPDATE vulnerability_manual_keywords SET enabled=? WHERE id=?",
        (1 if enabled else 0, keyword_id),
    )
    conn.commit()
    return {"id": keyword_id, "enabled": bool(enabled), "keyword": _fetch_keyword(conn, keyword_id)}


def delete_keyword(conn: sqlite3.Connection, keyword_id: int) -> bool:
    if not table_ready(conn):
        return False
    cursor = conn.execute("DELETE FROM vulnerability_manual_keywords WHERE id=?", (keyword_id,))
    conn.commit()
    return cursor.rowcount > 0


# ---------------------------------------------------------------- 采集侧合并


def load_manual_queries(conn: sqlite3.Connection, profile_name: str) -> list[str]:
    """取某个 profile 下**启用中**的人工关键词。

    该 profile 自己的词 + 挂在 `*`(所有 profile)上的词,按 id 升序(即添加顺序)。
    任何异常都吞掉返回 [] —— 采集主流程不该因为一张附属表读不出来就整晚不跑
    (与 pipelines/steps/threat_sources.py 里 merge_manual_targets 的兜底同一考虑)。
    """
    name = str(profile_name or "").strip()
    if not name:
        return []
    try:
        if not table_ready(conn):
            return []
        rows = conn.execute(
            "SELECT keyword FROM vulnerability_manual_keywords "
            "WHERE enabled=1 AND (profile_name=? OR profile_name=?) ORDER BY id",
            (name, WILDCARD_PROFILE),
        ).fetchall()
        return [str(row[0]) for row in rows if str(row[0] or "").strip()]
    except sqlite3.Error:
        return []


def merge_manual_queries(
    conn: sqlite3.Connection,
    profile_name: str,
    base_queries: list[str],
) -> tuple[list[str], dict[str, Any]]:
    """把人工关键词**前置**到 profile 自己的词前面,并去重(忽略大小写)。

    返回 (合并后的词表, 供 metrics 的统计)。人工词不参与下游截断,所以越靠前越安全;
    与 profile 已有的词重复时不重复下发(人工词保留原来的位置)。
    """
    manual = load_manual_queries(conn, profile_name)
    base = [str(query).strip() for query in (base_queries or []) if str(query or "").strip()]
    if not manual:
        return base, {"manual_queries": 0, "manual_merged": 0}
    seen = {query.casefold() for query in manual}
    merged = [*manual, *[query for query in base if query.casefold() not in seen]]
    return merged, {
        "manual_queries": len(manual),
        "manual_merged": len(merged) - len(base),
        "queries_after_merge": len(merged),
    }
