from __future__ import annotations

import os
import threading
from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Request
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
# 链路: 用户 → 8091(ASIS) → /insights/ rewrite → ai4sec:8100 → /repro-web/ → repro:8080
REPRO_WEB_UPSTREAM = os.environ.get("REPRO_WEB_UPSTREAM", "http://repro:8080")


async def repro_web_proxy(request: Request):
    """把 /repro-web/{path} 透明转发到 repro 容器内 agent 启动的 Web 服务(默认 8080)。"""
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
        resp = await client.request(request.method, url, headers=headers, content=body, stream=True)
    except Exception as e:  # noqa: BLE001 - 上游不可达给友好错误
        return JSONResponse({"detail": f"repro web upstream unreachable: {e}"}, status_code=502)
    resp_headers = {
        k: v for k, v in resp.headers.items()
        if k.lower() not in ("content-length", "transfer-encoding", "connection")
    }
    return StreamingResponse(
        resp.aiter_raw(),
        status_code=resp.status_code,
        headers=resp_headers,
        background=BackgroundTask(resp.aclose),
    )


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
    app.add_api_route(
        "/repro-web/{path:path}",
        repro_web_proxy,
        methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
        include_in_schema=False,
    )
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
    scheduler.add_job(_run_pipeline_job, CronTrigger(hour=22, minute=0), args=['vulnerabilities.full_knowledge_discovery_pipeline', {'keyword_profile': 'daily_watch'}], id='vuln', name='vuln(daily 22:00)', replace_existing=True)

    @app.on_event('startup')
    def _start_scheduler():
        scheduler.start()
        print('[scheduler] started: capability(15min), threat(daily 02:00), vuln(daily 22:00)', flush=True)

    @app.on_event('shutdown')
    def _stop_scheduler():
        scheduler.shutdown(wait=False)

    return app


app = create_app()
