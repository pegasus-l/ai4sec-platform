from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator

import requests
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.domains.capabilities.model_gateway import authorize_task_model_call, reconcile_task_model_usage
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
    reserved_tokens = estimated_input_tokens + requested_tokens
    grant = authorize_task_model_call(conn, token=token, model=model, requested_tokens=reserved_tokens)
    if not grant:
        raise HTTPException(status_code=401, detail="invalid, expired, revoked, or exhausted task model token")
    conn.commit()
    config = LLMRouter()._configured_model("configured_model")
    if not config:
        reconcile_task_model_usage(conn, token_id=int(grant["id"]), reserved_tokens=reserved_tokens, actual_tokens=0)
        conn.commit()
        raise HTTPException(status_code=503, detail="model gateway upstream is not configured")
    upstream_payload = {**payload, "model": config.model}
    if payload.get("stream"):
        upstream_payload["stream_options"] = {
            **(payload.get("stream_options") if isinstance(payload.get("stream_options"), dict) else {}),
            "include_usage": True,
        }
    headers = {"Authorization": f"Bearer {config.api_key}", "Content-Type": "application/json"}
    try:
        upstream = requests.post(
            f"{config.base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json=upstream_payload,
            timeout=config.timeout_seconds,
            stream=bool(payload.get("stream")),
        )
    except requests.RequestException as exc:
        reconcile_task_model_usage(conn, token_id=int(grant["id"]), reserved_tokens=reserved_tokens, actual_tokens=0)
        conn.commit()
        raise HTTPException(status_code=502, detail="model gateway upstream request failed") from exc
    if not upstream.ok:
        reconcile_task_model_usage(conn, token_id=int(grant["id"]), reserved_tokens=reserved_tokens, actual_tokens=0)
        conn.commit()
        return JSONResponse(status_code=upstream.status_code, content=_safe_json(upstream))
    if payload.get("stream"):
        return StreamingResponse(
            _stream_response(
                upstream,
                conn=conn,
                token_id=int(grant["id"]),
                reserved_tokens=reserved_tokens,
            ),
            media_type=upstream.headers.get("content-type", "text/event-stream"),
        )
    body = _safe_json(upstream)
    actual_tokens = _usage_tokens(body)
    reconcile_task_model_usage(
        conn,
        token_id=int(grant["id"]),
        reserved_tokens=reserved_tokens,
        actual_tokens=actual_tokens if actual_tokens is not None else reserved_tokens,
    )
    conn.commit()
    return JSONResponse(content=body)


def _stream_response(
    response,
    *,
    conn: sqlite3.Connection,
    token_id: int,
    reserved_tokens: int,
) -> Iterator[bytes]:
    actual_tokens: int | None = None
    try:
        for line in response.iter_lines():
            raw_line = line.encode() if isinstance(line, str) else line
            yield raw_line + b"\n"
            if not raw_line.startswith(b"data:"):
                continue
            data = raw_line.removeprefix(b"data:").strip()
            if not data or data == b"[DONE]":
                continue
            try:
                event = json.loads(data)
            except (ValueError, json.JSONDecodeError):
                continue
            usage_tokens = _usage_tokens(event)
            if usage_tokens is not None:
                actual_tokens = usage_tokens
    finally:
        reconcile_task_model_usage(
            conn,
            token_id=token_id,
            reserved_tokens=reserved_tokens,
            actual_tokens=actual_tokens if actual_tokens is not None else reserved_tokens,
        )
        conn.commit()
        response.close()


def _safe_json(response) -> dict:
    try:
        value = response.json()
        return value if isinstance(value, dict) else {"data": value}
    except (ValueError, json.JSONDecodeError):
        return {"error": {"message": response.text[:2000]}}


def _usage_tokens(payload: object) -> int | None:
    if not isinstance(payload, dict) or not isinstance(payload.get("usage"), dict):
        return None
    value = payload["usage"].get("total_tokens")
    try:
        tokens = int(value)
    except (TypeError, ValueError):
        return None
    return max(0, tokens)
