from __future__ import annotations

from fastapi import APIRouter

from ai4sec_platform.app.api import artifacts, capabilities, capability_eval, dashboard, health, internal, internal_eval, news, operations, ops, runs, threats, vulnerabilities, writeup_repro

api_router = APIRouter(prefix="/api")
api_router.include_router(health.router)
api_router.include_router(dashboard.router)
api_router.include_router(news.router)
api_router.include_router(capabilities.router)
api_router.include_router(capability_eval.router)
api_router.include_router(threats.router)
api_router.include_router(vulnerabilities.router)
api_router.include_router(writeup_repro.router)
api_router.include_router(operations.router)
api_router.include_router(ops.router)
api_router.include_router(runs.router)
api_router.include_router(artifacts.router)
api_router.include_router(internal.router)
api_router.include_router(internal_eval.router)
