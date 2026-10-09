from __future__ import annotations

from collections.abc import Iterator
import sqlite3

from fastapi import Request

from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect


def get_db() -> Iterator[sqlite3.Connection]:
    conn = connect()
    init_db(conn)
    try:
        yield conn
    finally:
        conn.close()


# 匿名占位:中间件没装(单测/直接调用)时也要能给"谁登记的"留个可辨认的值,
# 不能写空串 —— 空串在页面上看起来像"添加人未知",无法区分"没登录"和"没记录"。
ANONYMOUS_USER = "anonymous"


def current_user(request: Request) -> dict:
    """当前登录用户(由 ASISSessionMiddleware 写进 request.state.user)。

    新接口一律用这个拿"谁干的",不要下到 /api/internal/(那前缀不校验 cookie)。
    """
    user = getattr(request.state, "user", None)
    if isinstance(user, dict) and user.get("username"):
        return user
    return {"username": ANONYMOUS_USER, "role": "anonymous"}
