from __future__ import annotations
import hmac, hashlib, base64, json, os, time
from urllib.parse import quote
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, RedirectResponse

COOKIE_NAME = "sec_ai_hot_session"


# 入口网关(如 136 radar nginx)把 /insights 前缀剥掉后转发到本服务, 所以重定向回跳必须
# 按"浏览器可见路径"拼回去。两个值都可按部署覆盖, 默认值对应当前线上链路。
LOGIN_PATH = (os.environ.get("SEC_AI_LOGIN_URL") or "/login").strip() or "/login"
URL_PREFIX = (os.environ.get("SEC_AI_URL_PREFIX") or "/insights").strip().rstrip("/")


def _wants_html_navigation(headers) -> bool:
    """是否"浏览器导航"请求(地址栏/F5/点链接/iframe 文档)—— 只有这类才该被重定向到登录页。

    静态资源(CSS/JS/图片)、fetch/XHR、WebSocket 都不是导航, 重定向它们会直接把页面打坏。
    优先看 Sec-Fetch-Mode(现代浏览器必带): navigate 才是导航, cors/no-cors/same-origin 一律否;
    老浏览器没有该头时退回 Accept 判断。
    """
    mode = (headers.get("sec-fetch-mode") or "").strip().lower()
    if mode:
        return mode == "navigate"
    return "text/html" in (headers.get("accept") or "").lower()


def _browser_path(path: str, query: str, headers) -> str:
    """拼回浏览器可见的回跳路径: 优先用上游透传的 X-Original-URI, 否则 前缀 + 被剥掉的 path。"""
    original = headers.get("x-original-uri") or ""
    if original.startswith("/") and not original.startswith("//"):  # 防开放重定向
        return original
    target = f"{URL_PREFIX}{path}" if path.startswith("/") else f"{URL_PREFIX}/{path}"
    if not target.startswith("/"):
        target = "/" + target
    return f"{target}?{query}" if query else target


def login_redirect_url(path: str, query: str, headers) -> str:
    """未认证的导航请求 → 登录页(带 next 回跳), 与入口网关自己 307 的行为一致。"""
    return f"{LOGIN_PATH}?next={quote(_browser_path(path, query, headers), safe='')}"


class ASISSessionMiddleware(BaseHTTPMiddleware):
    """验证 ASIS 签名的 sec_ai_hot_session cookie。
    /api/* 验签失败 → 401 JSON; 非 /api/* 只在"浏览器导航"且未登录时 307 到登录页,
    静态资源/fetch/XHR/repro-web 放行。
    格式 v1.<base64url(payload)>.<base64url(HMAC-SHA256)>
    """

    def __init__(self, app, secret: str):
        super().__init__(app)
        self._secret = secret.encode()
        # 备用密钥(2026-09-16): 生产 ASIS(136:80) 与测试入口(136:8090)各自签发的会话用的
        # 是不同的 SEC_AI_SESSION_SECRET, 但都要能被本平台验签。env SEC_AI_SESSION_SECRET_ALT
        # 可用逗号分隔多个, 任一条验过即通过; 主密钥仍在首位(签名/兼容旧行为不变)。
        _alts = [
            s.strip()
            for s in (os.environ.get("SEC_AI_SESSION_SECRET_ALT") or "").split(",")
            if s.strip()
        ]
        self._secrets = [self._secret] + [a.encode() for a in _alts if a.encode() != self._secret]

    async def dispatch(self, request, call_next):
        path = request.url.path
        if request.method == "OPTIONS":
            return await call_next(request)
        # /api/internal/*: 容器间调用(复现容器看门狗轮询回收名单)。调用方是容器不是浏览器,
        # 故不参与用户会话(cookie)校验; 由路由自身用共享令牌 REPRO_PASSWORD 校验, 不对即 401。
        if path.startswith("/api/internal/"):
            return await call_next(request)
        # 前端页面/静态资源(非 /api/*): 未登录时**只有浏览器导航**跳登录页, 其余
        # (JS/CSS/图片、fetch/XHR)照旧放行 —— 给静态资源发重定向会把页面直接打坏。
        # /repro-web/* 排除: 那是由复现容器自己鉴权的 UI, 且可能被跨站 iframe 嵌入
        # (SameSite=Lax 下 iframe 不带 cookie), 重定向会误伤本来就正常的用法。
        if not path.startswith("/api/"):
            if (
                not path.startswith("/repro-web")
                and _wants_html_navigation(request.headers)
                and not self._verify(request.cookies.get(COOKIE_NAME) or "")
            ):
                return RedirectResponse(
                    login_redirect_url(path, request.url.query, request.headers),
                    status_code=307,
                )
            return await call_next(request)
        # /api/health 放行(健康检查)
        if path.endswith("/health"):
            return await call_next(request)
        # 其他 /api/* 验 cookie → 401 JSON(前端据此弹"登录已过期"横幅)
        cookie_val = request.cookies.get(COOKIE_NAME)
        user = self._verify(cookie_val) if cookie_val else None
        if not user:
            return JSONResponse({"error": "auth_required", "login": LOGIN_PATH}, status_code=401)
        request.state.user = user
        return await call_next(request)

    def _verify(self, value: str) -> dict | None:
        parts = value.split(".")
        if len(parts) != 3 or parts[0] != "v1":
            return None
        encoded_payload, signature = parts[1], parts[2]
        if not any(
            hmac.compare_digest(
                signature,
                base64.urlsafe_b64encode(
                    hmac.new(_s, encoded_payload.encode(), hashlib.sha256).digest()
                ).rstrip(b"=").decode(),
            )
            for _s in self._secrets
        ):
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
