"""评审降级时的待重评队列(2026-10-29)。

起因: 2026-10-28 模型网关整段返回 403, 而 `_fallback_review` 在这种情况下照旧返回
`decision="watch"` + `recommended_score=3` —— 下游 `StoreCapabilitiesStep` 把它当成一条
**有效评审**写进能力库。24 小时里实测灌进 1941 条「待资料补齐」空壳: 摘要为空、技术点为 0,
分数卡在 55-60, `score_reason` 写着「模型调用降级：HTTP Error 403: Forbidden」。
今日能力页首屏被这些卡片占满, 而它们从来没有被真正评过。

**降级评审不是评审结论, 它不该产出库条目。** 这里把这类候选连同**送模型的那份输入**存起来,
等模型恢复后重评(见 `RetryDegradedReviewsStep`)。存输入而不是事后重算: 原始记录要走 ASIS 的
导出接口按 raw id 找, 而 raw 游标每 15 分钟就往前走一趟, 那批数据事后拿不回来;
`model_calls` 里留着的是同一份输入的副本。

attempts 只在「模型确实回了话、但这次仍然不行」时累加; 整批都失败(网关宕了)按探活失败处理,
不烧 attempts —— 否则一次长宕机就能把队列里的候选全耗成永久放弃。
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

MAX_ATTEMPTS = 5

# 入队时只留重建条目 / 重评需要的字段: readme 与 raw 已经在 input_json 里, item_json 再存一份
# 就是双倍体积(候选上千条时按 MB 算)。
_ITEM_KEEP_KEYS = (
    "item_key", "title", "summary", "url", "source_url", "code_url", "source_type",
    "repo_full_name", "stars", "forks", "language", "topics", "authors",
    "primary_date", "published_at", "rule_score", "rule_breakdown",
    "security_flag", "security_topics", "category", "confidence",
)


def _now() -> str:
    return f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"


def prune_item(item: dict[str, Any]) -> dict[str, Any]:
    """候选 → 可入队的最小 item(保留重评与建条目要用的字段, 去掉 readme/raw 这类大字段)。"""
    return {k: item[k] for k in _ITEM_KEEP_KEYS if item.get(k) not in (None, "", [], {})}


def enqueue(
    conn: sqlite3.Connection,
    *,
    item: dict[str, Any],
    input_payload: dict[str, Any],
    reason: str,
    first_seen_at: str | None = None,
) -> str:
    """降级候选入队。同一 item_key 重复降级只刷新输入与原因, 不重置 attempts。"""
    item_key = str(item.get("item_key") or "")
    if not item_key:
        # 没有 item_key 就没法去重/重评, 直接抛给调用方记日志, 不静默吞
        raise ValueError("review backlog: item_key is empty")
    now = _now()
    conn.execute(
        """
        INSERT INTO capability_review_backlog
            (item_key, item_json, input_json, reason, attempts, last_error, first_seen_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, 0, '', ?, ?, ?)
        ON CONFLICT(item_key) DO UPDATE SET
            item_json = excluded.item_json,
            input_json = excluded.input_json,
            reason = excluded.reason,
            updated_at = excluded.updated_at
        """,
        (
            item_key,
            json.dumps(prune_item(item), ensure_ascii=False, default=str),
            json.dumps(input_payload, ensure_ascii=False, default=str),
            str(reason or ""),
            first_seen_at or now,
            now,
            now,
        ),
    )
    return item_key


def pending(conn: sqlite3.Connection, limit: int) -> list[dict[str, Any]]:
    """取待重评的批次: 先按 attempts 少的, 再按入队先后(先降级的先补)。"""
    rows = conn.execute(
        "SELECT id, item_key, item_json, input_json, reason, attempts, first_seen_at FROM capability_review_backlog "
        "ORDER BY attempts, id LIMIT ?",
        (int(limit),),
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        out.append({
            "id": int(row["id"]),
            "item_key": row["item_key"],
            "item": json.loads(row["item_json"] or "{}"),
            "input_payload": json.loads(row["input_json"] or "{}"),
            "reason": row["reason"],
            "attempts": int(row["attempts"] or 0),
            "first_seen_at": row["first_seen_at"],
        })
    return out


def remove(conn: sqlite3.Connection, row_id: int) -> None:
    conn.execute("DELETE FROM capability_review_backlog WHERE id = ?", (int(row_id),))


def record_failure(conn: sqlite3.Connection, row_id: int, error: str) -> bool:
    """记一次「模型回了话但这次仍失败」。达到 MAX_ATTEMPTS 就放弃, 返回是否已放弃。"""
    row = conn.execute("SELECT attempts FROM capability_review_backlog WHERE id = ?", (int(row_id),)).fetchone()
    if row is None:
        return False
    attempts = int(row["attempts"] or 0) + 1
    if attempts >= MAX_ATTEMPTS:
        remove(conn, row_id)
        return True
    conn.execute(
        "UPDATE capability_review_backlog SET attempts = ?, last_error = ?, updated_at = ? WHERE id = ?",
        (attempts, str(error or "")[:500], _now(), int(row_id)),
    )
    return False


def count(conn: sqlite3.Connection) -> int:
    return int(conn.execute("SELECT COUNT(*) FROM capability_review_backlog").fetchone()[0])
