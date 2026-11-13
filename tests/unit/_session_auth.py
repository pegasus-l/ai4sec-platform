"""单测用的会话票签名(不属于任何一条用例)。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time


def signed_client(role: str = "admin", username: str = "unit-test"):
    """带一张**自己签的会话票**的 TestClient。

    2026-10-31 起 `/api/*` 一律验 cookie, 裸 `TestClient(app)` 打过去每条都是 401 ——
    那不是接口坏了, 是用例没带身份。密钥取应用实际加载的那一个(中间件的 kwargs),
    硬编码会在配了 `SEC_AI_SESSION_SECRET` 的环境里静默失败。
    """
    from fastapi.testclient import TestClient

    from ai4sec_platform.app.main import app
    from ai4sec_platform.app.middleware import ASISSessionMiddleware, COOKIE_NAME

    middleware = next(m for m in app.user_middleware if m.cls is ASISSessionMiddleware)
    secret = str(middleware.kwargs.get("secret") or "").encode()
    payload = base64.urlsafe_b64encode(json.dumps(
        {"username": username, "role": role, "expiresAt": time.time() + 600},
    ).encode()).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(
        hmac.new(secret, payload.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return TestClient(app, cookies={COOKIE_NAME: f"v1.{payload}.{signature}"})
