from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ai4sec_platform.app.api.router import api_router
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from ai4sec_platform.app.middleware import ASISSessionMiddleware
from ai4sec_platform.core.env import load_env_file

load_env_file()

PROJECT_ROOT = Path(__file__).resolve().parents[3]
FRONTEND_DIST = PROJECT_ROOT / "frontend" / "dist"



def _run_pipeline_job(pipeline_name: str, params: dict | None = None) -> None:
    try:
        from ai4sec_platform.pipelines.runner import PipelineRunner
        r = PipelineRunner()
        result = r.run(pipeline_name, params=params or {})
        status = result.get('status', 'unknown')
        print(f'[scheduler] {pipeline_name}: {status}', flush=True)
    except Exception as e:
        print(f'[scheduler] {pipeline_name} error: {e}', flush=True)


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
