from __future__ import annotations
import hmac, hashlib, base64, json, time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

COOKIE_NAME = "sec_ai_hot_session"


class ASISSessionMiddleware(BaseHTTPMiddleware):
    """验证 ASIS 签名的 sec_ai_hot_session cookie。
    只对 /api/* 验证(API 鉴权), 前端页面/静态资源(非 /api/*)放行。
    格式 v1.<base64url(payload)>.<base64url(HMAC-SHA256)>
    """

    def __init__(self, app, secret: str):
        super().__init__(app)
        self._secret = secret.encode()

    async def dispatch(self, request, call_next):
        path = request.url.path
        if request.method == "OPTIONS":
            return await call_next(request)
        # 前端页面/静态资源(非 /api/*)放行
        if not path.startswith("/api/"):
            return await call_next(request)
        # /api/health 放行(健康检查)
        if path.endswith("/health"):
            return await call_next(request)
        # 其他 /api/* 验 cookie
        cookie_val = request.cookies.get(COOKIE_NAME)
        user = self._verify(cookie_val) if cookie_val else None
        if not user:
            return JSONResponse({"error": "auth_required", "login": "/login"}, status_code=401)
        request.state.user = user
        return await call_next(request)

    def _verify(self, value: str) -> dict | None:
        parts = value.split(".")
        if len(parts) != 3 or parts[0] != "v1":
            return None
        encoded_payload, signature = parts[1], parts[2]
        expected = base64.urlsafe_b64encode(
            hmac.new(self._secret, encoded_payload.encode(), hashlib.sha256).digest()
        ).rstrip(b"=").decode()
        if not hmac.compare_digest(signature, expected):
            return None
        try:
            padded = encoded_payload + "=" * (-len(encoded_payload) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
        except Exception:
            return None
        exp = payload.get("expiresAt")
        if not isinstance(exp, (int, float)) or exp <= time.time():
            return None
        return {
            "username": str(payload.get("username") or "unknown"),
            "role": str(payload.get("role") or "user"),
        }
