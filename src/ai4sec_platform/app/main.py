from __future__ import annotations

import asyncio
import os
import re
import threading
import urllib.parse
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.background import BackgroundTask

from ai4sec_platform.app.api.router import api_router
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from ai4sec_platform.app.middleware import ASISSessionMiddleware
from ai4sec_platform.core.env import load_env_file

load_env_file()

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"



_pipeline_lock = threading.Lock()

# ─── 复现 Web 服务反代: 用户从平台(/repro-web/*)打开复现容器里 agent 启动的 Web 界面 ───
# 链路: 用户 → 8091(ASIS) → /insights/ rewrite → ai4sec:8100 → /repro-web/{path} → repro:8080/{path}
REPRO_WEB_UPSTREAM = os.environ.get("REPRO_WEB_UPSTREAM", "http://repro:8080")
# ASIS 把 /insights/* rewrite 过来, 子路径前缀固定为 /insights/repro-web
REPRO_WEB_PREFIX = os.environ.get("REPRO_WEB_PREFIX", "/insights/repro-web")

# HTML 子路径适配: 很多 agent 启动的 SPA 用 root-absolute(/mail,/thread/x) 或相对(./static/...) 路径,
# 在 /insights/repro-web/ 子路径下会 404。这里注入 <base> 处理相对路径, 再给 root-absolute href/src 加前缀。
_REPRO_WEB_BASE_TAG = re.compile(r"<base\b", re.IGNORECASE)
_REPRO_WEB_HEAD = re.compile(r"<head[^>]*>", re.IGNORECASE)
# (href|src|action|data-src)="/xxx" → 加前缀; 跳过已带前缀(/insights/)、协议相对(//)、外部协议(http: 等)
# 注意组1只含 "attr=", 组2是引号; \1\2 拼回 "attr=quote/prefix/..."
_REPRO_WEB_ROOT_ATTR = re.compile(
    r"(\b(?:href|src|action|data-src)=)([\"'])/(?!/|insights/|[A-Za-z][A-Za-z0-9+.\-]*:)",
    re.IGNORECASE,
)


def _web_prefix(x_pathname: str | None, app_path: str) -> str:
    """从 ASIS middleware 写入的 x-pathname(原始路径)推导子路径前缀。

    例: x-pathname=/insights/repro-web/appwin.js, app_path=appwin.js → /insights/repro-web
         x-pathname=/insights/repro-web,        app_path=""          → /insights/repro-web
    """
    if not x_pathname:
        return REPRO_WEB_PREFIX
    prefix = x_pathname
    if app_path and prefix.endswith("/" + app_path):
        prefix = prefix[: -len(app_path) - 1]
    prefix = prefix.rstrip("/")
    if len(prefix.split("/")) >= 2:
        return prefix
    return REPRO_WEB_PREFIX


def _rewrite_web_html(html: str, prefix: str) -> str:
    """给 HTML 页面注入 <base href="{prefix}/"> 并把 root-absolute 链接改写成子路径, 返回改写结果。"""
    if not prefix:
        return html
    # 先改写 root-absolute 链接, 再注入 <base>: 若先注入 base, 注入的 href="/{prefix}/" 会被
    # root-attr 正则再次命中而二次加前缀(直连 /repro-web 时 base 变成 /repro-web/repro-web/, 静态资源全 404)。
    html = _REPRO_WEB_ROOT_ATTR.sub(rf"\1\2{prefix}/", html)
    if not _REPRO_WEB_BASE_TAG.search(html):
        base_tag = f'<base href="{prefix}/">'
        m = _REPRO_WEB_HEAD.search(html)
        html = html[: m.end()] + base_tag + html[m.end():] if m else base_tag + html
    return html


async def repro_web_proxy(request: Request):
    """把 /repro-web/{path} 转发到 repro 容器内 agent 启动的 Web 服务(默认 8080)。

    对 HTML 响应做子路径适配(注入 <base> + root-absolute 链接加前缀), 使 SPA 在
    /insights/repro-web/ 下完整可用; 非 HTML 按原样流式透传。
    """
    app = request.app
    client = getattr(app.state, "repro_web_client", None)
    if client is None:
        client = httpx.AsyncClient(timeout=None, follow_redirects=False)
        app.state.repro_web_client = client
    path = request.path_params.get("path", "")
    url = f"{REPRO_WEB_UPSTREAM}/{path}"
    if request.url.query:
        url += f"?{request.url.query}"
    # 转发请求头(去掉 hop-by-hop), 按原文回传响应头; 不用 gzip 以便流式逐块转发
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in ("host", "content-length", "connection", "accept-encoding")
    }
    headers["accept-encoding"] = "identity"
    body = await request.body()
    try:
        req = client.build_request(request.method, url, headers=headers, content=body)
        resp = await client.send(req, stream=True)
    except Exception as e:  # noqa: BLE001 - 上游不可达给友好错误
        return JSONResponse({"detail": f"repro web upstream unreachable: {e}"}, status_code=502)
    resp_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in ("content-length", "transfer-encoding", "connection")
    }
    status = resp.status_code
    ctype = (resp.headers.get("content-type") or "").lower()
    # 仅 GET 成功响应的 text/html 才做子路径适配; 其余(静态资源/接口/错误页)按原文透传
    if "text/html" in ctype and "json" not in ctype and status < 400 and request.method in ("GET", "HEAD"):
        try:
            data = await resp.aread()
        finally:
            await resp.aclose()
        if data:
            # ASIS 走 /insights/* 时由 middleware 注入 x-pathname; 直连 /repro-web/* 时用请求路径兜底,
            # 否则 base href 会错指向 /insights/repro-web 导致静态资源 404 / MIME 拒绝(实测页面空白)。
            prefix = _web_prefix(request.headers.get("x-pathname") or request.url.path, path)
            text = data.decode("utf-8", errors="replace")
            rewritten = _rewrite_web_html(text, prefix)
            if rewritten != text:
                data = rewritten.encode("utf-8")
            resp_headers["content-length"] = str(len(data))
            return StreamingResponse(iter([data]), status_code=status, headers=resp_headers)
    return StreamingResponse(
        resp.aiter_raw(),
        status_code=status,
        headers=resp_headers,
        background=BackgroundTask(resp.aclose),
    )


async def repro_web_ws_proxy(websocket: WebSocket) -> None:
    """WebSocket 反代: 浏览器 /repro-web/{path} → repro 容器 8080。

    httpx 无法转发 WS 升级(实测 /repro-web/_stcore/stream 只回 200, Streamlit 页面空白根因),
    这里用 websockets 客户端做双向隧道, 浏览器 → ai4sec → repro 容器 全链路 101。
    """
    import websockets
    from websockets.exceptions import ConnectionClosed

    path = websocket.path_params.get("path", "")
    base = REPRO_WEB_UPSTREAM.replace("http://", "ws://").replace("https://", "wss://")
    url = f"{base}/{path}"
    if websocket.query_params:
        url += "?" + urllib.parse.urlencode(list(websocket.query_params.items()))
    extra_headers = None
    cookie = websocket.headers.get("cookie")
    if cookie:
        extra_headers = {"Cookie": cookie}
    client_subprotocols = list(websocket.scope.get("subprotocols") or [])
    try:
        await websocket.accept(subprotocol=client_subprotocols[0] if client_subprotocols else None)
    except Exception:  # noqa: BLE001 - 客户端先断开则直接放弃
        return

    try:
        async with websockets.connect(
            url, additional_headers=extra_headers, subprotocols=client_subprotocols or None
        ) as upstream:
            async def pump_upstream() -> None:
                """repro 容器 → 浏览器。"""
                try:
                    while True:
                        msg = await upstream.recv()
                        if isinstance(msg, str):
                            await websocket.send_text(msg)
                        else:
                            await websocket.send_bytes(msg)
                except ConnectionClosed:
                    pass
                except Exception:  # noqa: BLE001
                    pass

            async def pump_client() -> None:
                """浏览器 → repro 容器。"""
                try:
                    while True:
                        data = await websocket.receive()
                        if data["type"] == "websocket.disconnect":
                            break
                        msg = data.get("text") or data.get("bytes")
                        if msg is not None:
                            await upstream.send(msg)
                except Exception:  # noqa: BLE001
                    pass

            await asyncio.gather(pump_upstream(), pump_client())
    except Exception:  # noqa: BLE001 - 上游连不上/中途断开给浏览器干净关闭
        try:
            await websocket.close(code=1011)
        except Exception:  # noqa: BLE001
            pass


def _run_pipeline_job(pipeline_name: str, params: dict | None = None) -> None:
    acquired = _pipeline_lock.acquire(timeout=600)
    if not acquired:
        print(f'[scheduler] {pipeline_name}: skipped (another pipeline running)', flush=True)
        return
    try:
        from ai4sec_platform.pipelines.runner import PipelineRunner
        r = PipelineRunner()
        result = r.run(pipeline_name, params=params or {})
        status = result.get('status', 'unknown')
        print(f'[scheduler] {pipeline_name}: {status}', flush=True)
    except Exception as e:
        print(f'[scheduler] {pipeline_name} error: {e}', flush=True)
    finally:
        _pipeline_lock.release()


def create_app() -> FastAPI:
    app = FastAPI(title="AI4SEC Platform", version="0.1.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(
        ASISSessionMiddleware,
        secret=os.environ.get("SEC_AI_SESSION_SECRET", ""),
    )
    app.include_router(api_router)
    # 复现 Web 服务反代(必须注册在 catch-all /{path:path} 之前)
    # 无斜杠 /repro-web 和带斜杠 /repro-web/ 都匹配: ASIS rewrite 会产生无斜杠路径, 不能让它落到 catch-all
    app.add_api_route(
        "/repro-web",
        repro_web_proxy,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )
    app.add_api_route(
        "/repro-web/{path:path}",
        repro_web_proxy,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )
    # WS 反代(与 HTTP 反代同路径, uvicorn 按 Upgrade 分派): Streamlit 等 Web 界面的 _stcore/stream
    app.add_api_websocket_route("/repro-web", repro_web_ws_proxy)
    app.add_api_websocket_route("/repro-web/{path:path}", repro_web_ws_proxy)
    if (FRONTEND_DIST / "assets").exists():
        app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(FRONTEND_DIST / "index.html", headers={"Cache-Control": "no-store"})

    @app.get("/{path:path}", include_in_schema=False)
    def frontend_fallback(path: str) -> FileResponse:
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="API route not found")
        target = FRONTEND_DIST / path
        if target.exists() and target.is_file():
            return FileResponse(target)
        return FileResponse(FRONTEND_DIST / "index.html", headers={"Cache-Control": "no-store"})

    # APScheduler: pipeline scheduling
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(_run_pipeline_job, IntervalTrigger(minutes=15), args=['capabilities.from_news_pipeline'], id='cap', name='capability(15min)', replace_existing=True)
    scheduler.add_job(_run_pipeline_job, CronTrigger(hour=2, minute=0), args=['threats.huawei_full_migration_pipeline'], id='threat', name='threat(daily 02:00)', replace_existing=True)
    scheduler.add_job(_run_pipeline_job, CronTrigger(hour=22, minute=0), args=['vulnerabilities.full_knowledge_discovery_pipeline', {'keyword_profile': 'daily_watch', 'skip_existing_urls': True}], id='vuln', name='vuln(daily 22:00)', replace_existing=True)

    @app.on_event('startup')
    def _start_scheduler():
        scheduler.start()
        # 容器重建/重启会把在跑的复现 runner 线程杀死(任务卡 running/queued), 而 serve 端 agent
        # 会继续跑并烧 token(实测 task 13: runner 死于容器 recreate, agent 白烧 90min/$2.1)。
        # 启动时清扫孤儿任务: 抢救已产出文本→诚实判定→中止 serve 会话止损。
        try:
            from ai4sec_platform.pipelines.steps.repro import recover_orphaned_tasks
            n = recover_orphaned_tasks()
            print(f'[repro-recover] {n} orphaned repro task(s) recovered', flush=True)
        except Exception as e:  # noqa: BLE001 - 清扫失败不影响启动
            print(f'[repro-recover] error: {e}', flush=True)
        print('[scheduler] started: capability(15min), threat(daily 02:00), vuln(daily 22:00)', flush=True)

    @app.on_event('shutdown')
    def _stop_scheduler():
        scheduler.shutdown(wait=False)

    return app


app = create_app()
