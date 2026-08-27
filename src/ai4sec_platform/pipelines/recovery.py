from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.session import connect


def recover_orphaned_pipeline_runs(settings: Settings | None = None) -> int:
    """启动清扫: 全新进程里任何 queued/running 的 pipeline_run 都是孤儿(调度线程随旧进程消亡)。

    容器重建/重启把在跑的 runner 线程杀掉, 但 DB 行仍卡 running(实测 14 个僵尸)。
    应用启动时全部标记 interrupted, 写 finished_at + 原因, 保证无 running 行在重启后存活。
    返回清扫数量。
    """
    conn = connect(settings or load_settings())
    recovered = 0
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        rows = conn.execute(
            "SELECT * FROM pipeline_runs WHERE status IN ('queued','running')"
        ).fetchall()
        for row in rows:
            _interrupt_run(conn, row, reason="孤儿回收: 进程启动清扫(容器重启/重建遗留)")
            recovered += 1
        if recovered:
            conn.commit()
    finally:
        conn.close()
    return recovered


def reap_stale_pipeline_runs(
    settings: Settings | None = None,
    *,
    stale_after_seconds: float = 21600.0,
    max_run_age_seconds: float = 86400.0,
    min_age_seconds: float = 300.0,
) -> int:
    """周期性看门狗: 回收"悬挂"的 pipeline_run, 保证任何 run 最终到达终态。

    判死两种:
      1) 心跳(last_progress_at)停滞超过 stale_after_seconds → 疑似卡死;
      2) run 总时长超过 max_run_age_seconds → 超时兜底。
    min_age_seconds 防启动窗口误杀(刚启动的健康 run)。
    返回回收数量。
    """
    conn = connect(settings or load_settings())
    reaped = 0
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        now = time.time()
        rows = conn.execute(
            "SELECT * FROM pipeline_runs WHERE status IN ('queued','running')"
        ).fetchall()
        for row in rows:
            started = _parse_utc(row["started_at"]) or now
            age = now - started
            if age < min_age_seconds:
                continue
            summary = repo.loads(row["summary_json"], {}) or {}
            last = _parse_utc(summary.get("last_progress_at")) or started
            silent = now - last
            if age > max_run_age_seconds:
                _interrupt_run(conn, row, reason=f"看门狗回收: run 超过最大时长 {max_run_age_seconds:g}s")
                reaped += 1
            elif silent > stale_after_seconds:
                _interrupt_run(conn, row, reason=f"看门狗回收: 心跳停滞 {silent:g}s, 判定为悬挂")
                reaped += 1
        if reaped:
            conn.commit()
    finally:
        conn.close()
    return reaped


def _interrupt_run(conn, row: Any, *, reason: str) -> None:
    """把一条 run 翻成 interrupted 终态。

    复用 repo.create_pipeline_run 的 upsert(已确认 SELECT→UPDATE/INSERT), 无需 schema 迁移;
    保留原 started_at, 写 finished_at + summary.error_message。
    """
    summary = repo.loads(row["summary_json"], {}) or {}
    summary.update({"status": "interrupted", "error_message": reason, "interrupted_at": utc_now()})
    repo.create_pipeline_run(
        conn,
        run_id=row["run_id"],
        domain=row["domain"],
        pipeline_name=row["pipeline_name"],
        status="interrupted",
        started_at=row["started_at"],
        finished_at=utc_now(),
        production_writes=False,
        summary=summary,
    )


def _parse_utc(value: str | None) -> float | None:
    """把 DB 里 ISO 格式 UTC 时间转成 epoch 秒; 无法解析返回 None。"""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None
