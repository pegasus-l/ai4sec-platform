"""容器间内部接口(不面向浏览器, 不参与用户会话校验)。

/repro-gc —— repro 容器看门狗(每 10s)拉取「哪些任务目录该留、哪些该收」的权威名单。
复现产物落在 repro 容器的卷里(/workspace/repo-{id}), 而「这条任务还算不算数」只写在平台 DB,
两边没有共享文件系统; 平台侧也没有 docker CLI/套接字, 无法反向删目录。因此由 repro 侧轮询。

鉴权: 共享令牌走 X-Repro-Token 头, 值取平台 env 的 REPRO_PASSWORD —— 该值 repro 容器同样持有
(那边叫 OPENCODE_SERVER_PASSWORD, opencode serve 的 Basic 口令), 所以无需新增任何配置。
路径前缀 /api/internal/ 在 middleware 里直接放行(不做 cookie 校验), 由本模块自校验令牌。
"""
from __future__ import annotations

import hmac
import os
import sqlite3
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException

from ai4sec_platform.app.dependencies import get_db

router = APIRouter(prefix="/internal", tags=["internal"])

# 目录必须留下的任务状态: 在跑 / 排队 / 已复现成功(页面上挂着可打开的界面)。
# 注意不能用 web_url 判活 —— 实测 task#1006(partial, 审脉AuditPilot)web_url 是空的但服务在跑,
# 按 web_url 判会把线上还开着的界面删掉。
_KEEP_STATUSES = {"running", "queued", "success", "partial"}
# 刚点过清理: 给 runner 的 abort 一点落地时间, 本轮先不删目录(避免从正在收尾的 agent 脚下抽目录)
_CLEAN_GRACE_SECONDS = 120
# 无界面可开的终态(failed/error/timeout/stopped/not_supported): 目录留一段人工查看期再回收
_NO_WEB_RETENTION_SECONDS = 24 * 3600


def _require_token(token: str) -> None:
    expected = os.environ.get("REPRO_PASSWORD", "")
    if not expected:
        raise HTTPException(status_code=503, detail="REPRO_PASSWORD not configured")
    if not hmac.compare_digest(token or "", expected):
        raise HTTPException(status_code=401, detail="bad token")


def _age_seconds(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        t = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - t).total_seconds()
    except Exception:  # noqa: BLE001 - 时间戳坏掉视为无时间信息(走保守分支)
        return None


@router.get("/repro-gc")
def repro_gc(x_repro_token: str = Header(""), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """repro 看门狗回收任务目录的权威名单。

    keep = 绝不动(在跑 / 已复现成功 / 刚清理完还在保护期)
    reap = 现在可回收(已作废且过了保护期)
    两个名单都没有的 repo-{id} 目录 = 平台不认识的残留, 由 repro 侧按目录年龄自行处置。
    """
    _require_token(x_repro_token)
    keep: list[int] = []
    reap: list[int] = []
    rows = conn.execute(
        "SELECT id, status, cleaned_at, finished_at, created_at FROM capability_repro_tasks"
    ).fetchall()
    for task_id, status, cleaned_at, finished_at, created_at in rows:
        status = str(status or "")
        if status in _KEEP_STATUSES:
            keep.append(task_id)
            continue
        age = _age_seconds(cleaned_at or finished_at or created_at)
        if status == "cleaned":
            # 保护期只对"刚点的清理"有用; 早先清掉的历史遗留(age 很大)立刻回收
            if age is not None and age >= _CLEAN_GRACE_SECONDS:
                reap.append(task_id)
            else:
                keep.append(task_id)
        elif age is not None and age >= _NO_WEB_RETENTION_SECONDS:
            reap.append(task_id)
        else:
            keep.append(task_id)
    return {
        "keep": keep,
        "reap": reap,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
