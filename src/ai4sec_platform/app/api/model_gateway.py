from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator

import requests
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.domains.capabilities.model_gateway import authorize_task_model_call
from ai4sec_platform.models.router import LLMRouter


router = APIRouter(prefix="/model-gateway/v1", tags=["model-gateway"])


@router.post("/chat/completions")
def chat_completions(
    request: Request,
    payload: dict,
    authorization: str = Header(default=""),
    conn: sqlite3.Connection = Depends(get_db),
):
    token = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else ""
    model = str(payload.get("model") or "")
    requested_tokens = max(0, int(payload.get("max_tokens") or payload.get("max_completion_tokens") or 0))
    estimated_input_tokens = max(1, len(json.dumps(payload.get("messages") or [], ensure_ascii=False)) // 4)
    grant = authorize_task_model_call(conn, token=token, model=model, requested_tokens=estimated_input_tokens + requested_tokens)
    if not grant:
        raise HTTPException(status_code=401, detail="invalid, expired, revoked, or exhausted task model token")
    conn.commit()
    config = LLMRouter()._configured_model("configured_model")
    if not config:
        raise HTTPException(status_code=503, detail="model gateway upstream is not configured")
    upstream_payload = {**payload, "model": config.model}
    headers = {"Authorization": f"Bearer {config.api_key}", "Content-Type": "application/json"}
    upstream = requests.post(
        f"{config.base_url.rstrip('/')}/chat/completions",
        headers=headers,
        json=upstream_payload,
        timeout=config.timeout_seconds,
        stream=bool(payload.get("stream")),
    )
    if not upstream.ok:
        return JSONResponse(status_code=upstream.status_code, content=_safe_json(upstream))
    if payload.get("stream"):
        return StreamingResponse(_stream_response(upstream), media_type=upstream.headers.get("content-type", "text/event-stream"))
    body = _safe_json(upstream)
    return JSONResponse(content=body)


def _stream_response(response) -> Iterator[bytes]:
    try:
        yield from response.iter_content(chunk_size=8192)
    finally:
        response.close()


def _safe_json(response) -> dict:
    try:
        value = response.json()
        return value if isinstance(value, dict) else {"data": value}
    except (ValueError, json.JSONDecodeError):
        return {"error": {"message": response.text[:2000]}}
