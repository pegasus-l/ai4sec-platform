from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from typing import Any

from ai4sec_platform.core.time import utc_now


def issue_task_model_token(
    conn: sqlite3.Connection,
    *,
    task_id: int,
    model: str,
    ttl_seconds: int,
    max_calls: int,
    max_tokens: int,
) -> str:
    if not model or not 60 <= ttl_seconds <= 14_400 or not 1 <= max_calls <= 1_000 or not 1_000 <= max_tokens <= 10_000_000:
        raise ValueError("invalid repro model token limits")
    token = f"rmt_{secrets.token_urlsafe(32)}"
    now = utc_now()
    conn.execute("UPDATE repro_model_tokens SET revoked_at = ?, updated_at = ? WHERE task_id = ? AND revoked_at = ''", (now, now, task_id))
    conn.execute(
        """
        INSERT INTO repro_model_tokens(
            task_id, token_hash, model, max_calls, max_tokens, expires_at, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (task_id, _token_hash(token), model, max_calls, max_tokens, int(time.time()) + ttl_seconds, now, now),
    )
    return token


def authorize_task_model_call(conn: sqlite3.Connection, *, token: str, model: str, requested_tokens: int) -> dict[str, Any] | None:
    requested_tokens = max(0, requested_tokens)
    now_epoch = int(time.time())
    now = utc_now()
    cursor = conn.execute(
        """
        UPDATE repro_model_tokens
        SET calls_used = calls_used + 1, tokens_used = tokens_used + ?, updated_at = ?
        WHERE token_hash = ? AND model = ? AND revoked_at = '' AND expires_at > ?
          AND calls_used < max_calls AND tokens_used + ? <= max_tokens
        """,
        (requested_tokens, now, _token_hash(token), model, now_epoch, requested_tokens),
    )
    if cursor.rowcount != 1:
        return None
    row = conn.execute("SELECT * FROM repro_model_tokens WHERE token_hash = ?", (_token_hash(token),)).fetchone()
    return dict(row) if row else None


def record_task_model_usage(conn: sqlite3.Connection, *, token_id: int, additional_tokens: int) -> None:
    if additional_tokens <= 0:
        return
    conn.execute(
        "UPDATE repro_model_tokens SET tokens_used = MIN(max_tokens, tokens_used + ?), updated_at = ? WHERE id = ?",
        (additional_tokens, utc_now(), token_id),
    )


def revoke_task_model_tokens(conn: sqlite3.Connection, *, task_id: int) -> None:
    now = utc_now()
    conn.execute("UPDATE repro_model_tokens SET revoked_at = ?, updated_at = ? WHERE task_id = ? AND revoked_at = ''", (now, now, task_id))


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
