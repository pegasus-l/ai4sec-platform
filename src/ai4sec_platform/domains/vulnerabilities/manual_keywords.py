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
  新列走 db/models 的 `init_db` 里的 ALTER(表已存在时 CREATE 补不了列)。

## 2026-10-16 增补:范围语义、去重、生效证据

起因:这个页面把**实现概念 profile** 暴露成了用户必须做的决定。核查后的事实是 ——
唯一的定时漏洞跑批(app/main.py 的 CronTrigger)写死 `keyword_profile=daily_watch`,
其余 profile 生产跑批各 0 次;而取数 SQL 是 `profile_name=? OR profile_name='*'`,
所以**选 daily_watch 和选 `*` 在当前系统里等价**,下拉框给的是一个没有后果的选择。
同时还有三个真问题,一起修掉:

1. **跨范围重复**(两个侧都堵):同一个词挂在两个范围下时,取数会把两行都带出来 ——
   ① 写入口 `add_keyword` 直接拦掉,返回 `existing_scope` 指向已存在那条,不再插新行;
   ② `merge_manual_queries` 读取侧再兜一次,人工词内部按大小写去重(此前只与 base 去重,
   **两条一样的人工词会原样下发两遍**)。
2. **"启用"不等于"生效"**:挂在不跑的 profile 上的词永远不会被搜,页面此前只显示绿色
   「启用」徽章 —— 这正是上面第 17 行说的那类坑的另一半。现在由
   `mark_manual_queries_used()` 在**真要下发的那一刻**盖 `last_used_at`,页面据此显示
   「从未下发」。**只读预览绝不能调它**,否则证据变假。
3. **上限口径**:`MAX_PER_PROFILE` 是**按 profile_name 分组**算的,`*` 与具体 profile
   各占一份额度,所以每晚实际下发量可以到 50+20+20。页面文案要按这个口径写,别写成
   "每个 profile 总共最多 20 条"。
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
# **每晚定时跑批用的 profile**(2026-10-16)。此前这个字面量硬编码在
# app/main.py 的 CronTrigger 里、页面又各自猜一份,两边会漂;现在只在这里定义一处,
# main.py 的调度注册与 API 的"今晚下发几条"预览都引用它。
NIGHTLY_PROFILE = "daily_watch"


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
            last_used_at TEXT NOT NULL DEFAULT '',
            last_used_profile TEXT NOT NULL DEFAULT '',
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
        # 生效证据(2026-10-16):空串 = 从未下发。索引兜底必须与 _SELECT_COLUMNS 同序。
        "last_used_at": str(get("last_used_at", 8) or ""),
        "last_used_profile": str(get("last_used_profile", 9) or ""),
    }


_SELECT_COLUMNS = "SELECT id, profile_name, keyword, label, note, enabled, created_by, created_at, last_used_at, last_used_profile FROM vulnerability_manual_keywords"


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
    # **跨范围**查重(2026-10-16):同一个词挂在两个范围下(既在 `*` 又在 daily_watch)时,
    # 取数 SQL(load_manual_queries 的 `profile_name=? OR profile_name='*'`)会把两行都带出来。
    # 合并侧虽然已按大小写去重(见 merge_manual_queries),但列表里仍会出现两条看起来一样、
    # 只有范围不同的记录,用户无从判断哪条在起作用。所以在**写入口**直接拦掉,把已存在的那条
    # 指回给调用方(existing_scope),不再插新行。
    # 已存在那条若是停用状态,按上面的同一套幂等约定重新启用 —— `*` 是任何 profile 的超集,
    # 挂在它上面同样保证每晚被搜到,没必要再插一条重复行。
    other = conn.execute(
        "SELECT id, profile_name, enabled FROM vulnerability_manual_keywords "
        "WHERE keyword=? AND profile_name<>? ORDER BY id LIMIT 1",
        (clean, profile),
    ).fetchone()
    if other:
        other_id, other_profile, other_enabled = int(other[0]), str(other[1] or ""), bool(other[2])
        if not other_enabled:
            conn.execute("UPDATE vulnerability_manual_keywords SET enabled=1 WHERE id=?", (other_id,))
            conn.commit()
        return {
            "keyword": _fetch_keyword(conn, other_id),
            "created": False,
            "existing_scope": other_profile,
        }
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
    # 人工词**自己**也要去重(2026-10-16):同一个词可能分别挂在 `*` 和某个具体 profile 上,
    # 而 load_manual_queries 的 `profile_name=? OR profile_name='*'` 会把两行都取出来。
    # 此前只做了"人工词 vs base"的去重,**两条一模一样的人工词会原样下发两遍**
    # (白烧一次搜索与会话额度)。写入口已拦掉新的跨范围重复,这里再兜一次读取侧,
    # 因为历史数据与直接写库仍可能造成这种状态。保留首次出现的那条(即 id 最小的)。
    seen: set[str] = set()
    manual_deduped: list[str] = []
    for query in manual:
        key = query.casefold()
        if key not in seen:
            seen.add(key)
            manual_deduped.append(query)
    merged = [*manual_deduped, *[query for query in base if query.casefold() not in seen]]
    return merged, {
        # 注意这里报的是**去重前**的启用条数,便于和页面上显示的条数对照;
        # 真正进下发的数量看 manual_merged / queries_after_merge。
        "manual_queries": len(manual),
        "manual_merged": len(merged) - len(base),
        "queries_after_merge": len(merged),
    }


def mark_manual_queries_used(conn: sqlite3.Connection, profile_name: str) -> None:
    """给"这条词真的被下发过"留证据(2026-10-16)。

    把该 profile 下**启用中**的人工词(自己的 + 挂在 `*` 上的)盖上 last_used_at 与
    last_used_profile。**不需要传下发词表**:merge_manual_queries 的去重永远是丢 base 那一份、
    保留人工那一份,所以每个启用的行都确实进了这一次的下发集合。

    **调用时机 = 采集真要下发查询表的那一刻**(见 pipelines/steps/vulnerability_discovery.py
    与 vulnerability_batch.py 里紧跟在 merge 之后的位置)。**只读的预览路径绝不能调它** ——
    否则页面一打开就把所有词标成"已下发",这个证据就失去意义了。

    **不自己 commit()**:runner 在每个 step 结束后都会提交,跟着既有提交点落盘即可,不改变
    事务语义。代价是进程在提交前猝死会丢这条证据 —— 可接受,它是监控字段,不是业务数据。
    写失败一律吞掉:采集主流程不能因为一张附属表写不进去就整晚不跑(与 load_manual_queries 同理)。
    """
    name = str(profile_name or "").strip()
    if not name:
        return
    try:
        if not table_ready(conn):
            return
        conn.execute(
            "UPDATE vulnerability_manual_keywords SET last_used_at=?, last_used_profile=? "
            "WHERE enabled=1 AND (profile_name=? OR profile_name=?)",
            (repo.utc_now(), name, name, WILDCARD_PROFILE),
        )
    except sqlite3.Error:
        return
