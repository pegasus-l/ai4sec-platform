"""会话过期被伪装成 403 的回归测试(2026-10-31)。

线上现象: 点「项目复现」返回 403「当前会话只读」, 且怎么刷新都不跳登录页。
根因: cookie 过期后中间件静默回退到入口网关的嵌入票(viewer), 写操作于是 403 而非 401,
前端只认 401 ⇒ 没有任何提示。这里锁住三件事:

1. 靠嵌入票进来的写操作, 403 必须带 reason=session_expired(前端据此提示重新登录);
2. 有效 cookie 但角色只读, 403 带 reason=insufficient_role(重新登录没用, 别误导);
3. 只读会话的读请求照常放行 —— 否则整页会同时炸掉。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from ai4sec_platform.app.middleware import (
    ASISSessionMiddleware,
    COOKIE_NAME,
    EMBED_TICKET_HEADER,
)

SECRET = "unit-test-secret"


def _sign(payload: dict) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(
        hmac.new(SECRET.encode(), encoded.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"v1.{encoded}.{signature}"


def _session(role: str = "admin", ttl: float = 600) -> str:
    return _sign({"username": "tester", "role": role, "expiresAt": time.time() + ttl})


def _client() -> TestClient:
    app = FastAPI()
    app.add_middleware(ASISSessionMiddleware, secret=SECRET)

    @app.get("/api/read")
    def read() -> dict:
        return {"ok": True}

    @app.post("/api/write")
    def write() -> dict:
        return {"ok": True}

    return TestClient(app)


def test_admin_cookie_can_write() -> None:
    client = _client()
    client.cookies.set(COOKIE_NAME, _session("admin"))
    assert client.post("/api/write").status_code == 200


def test_viewer_cookie_write_is_forbidden_for_role_not_expiry() -> None:
    """登录有效、账号只读 —— 这是"权限不足", 不是"掉线了", 重登没用。"""
    client = _client()
    client.cookies.set(COOKIE_NAME, _session("user"))
    response = client.post("/api/write")
    assert response.status_code == 403
    body = response.json()
    assert body["error"] == "read_only_session"
    assert body["reason"] == "insufficient_role"


def test_expired_cookie_falls_back_to_ticket_and_reports_session_expired() -> None:
    """线上真实路径: cookie 过期 → 回退到入口网关嵌入票 → 写操作 403, 但原因是掉线。"""
    client = _client()
    client.cookies.set(COOKIE_NAME, _session("admin", ttl=-10))  # 已过期
    response = client.post("/api/write", headers={EMBED_TICKET_HEADER: _session("viewer")})
    assert response.status_code == 403
    body = response.json()
    assert body["error"] == "read_only_session"
    assert body["reason"] == "session_expired"
    assert body["login"]  # 前端拿它拼登录入口


def test_read_still_works_for_expired_cookie_with_ticket() -> None:
    """只读会话的读请求必须放行, 否则用户整页都打不开。"""
    client = _client()
    client.cookies.set(COOKIE_NAME, _session("admin", ttl=-10))
    response = client.get("/api/read", headers={EMBED_TICKET_HEADER: _session("viewer")})
    assert response.status_code == 200


def test_no_session_at_all_is_still_401() -> None:
    """既没 cookie 也没票 → 401(前端弹"登录已过期"横幅)。"""
    response = _client().post("/api/write")
    assert response.status_code == 401
    assert response.json()["error"] == "auth_required"
