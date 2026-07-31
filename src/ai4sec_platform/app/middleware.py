from __future__ import annotations
import hmac, hashlib, base64, json, time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

COOKIE_NAME = "sec_ai_hot_session"
PUBLIC_PATHS = {"/api/health", "/health", "/insights/api/health"}


class ASISSessionMiddleware(BaseHTTPMiddleware):
    """验证 ASIS 签名的 sec_ai_hot_session cookie。
    复现 ASIS apps/web/lib/auth.ts: 格式 v1.<base64url(payload)>.<base64url(HMAC-SHA256)>
    方案 B: 自验 cookie(必透传), 不依赖 ASIS middleware 注入的 x-user header。
    """

    def __init__(self, app, secret: str):
        super().__init__(app)
        self._secret = secret.encode()

    async def dispatch(self, request, call_next):
        path = request.url.path
        # 放行 CORS 预检 + 健康检查
        if request.method == "OPTIONS" or any(path.endswith(p) for p in PUBLIC_PATHS):
            return await call_next(request)
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
