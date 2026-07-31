from __future__ import annotations

import random
import socket
import time
from collections.abc import Callable
from typing import TypeVar
import urllib.error
import urllib.request

ResultType = TypeVar("ResultType")


def retry_call(operation: Callable[[], ResultType], *, attempts: int = 3, base_delay_seconds: float = 1.0, jitter_seconds: float = 0.5, max_delay_seconds: float = 30.0) -> ResultType:
    last_error: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            return operation()
        except Exception as exc:
            last_error = exc
            if attempt >= attempts or not is_retryable_source_error(exc):
                raise
            retry_after = _retry_after_seconds(exc)
            delay = retry_after if retry_after is not None else base_delay_seconds * (2 ** (attempt - 1)) + random.uniform(0, jitter_seconds)
            delay = min(max_delay_seconds, max(0.0, delay))
            time.sleep(delay)
    raise RuntimeError(str(last_error))


def is_retryable_source_error(exc: Exception) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code == 429 or 500 <= exc.code <= 599
    if isinstance(exc, (TimeoutError, socket.timeout, urllib.error.URLError, ConnectionError)):
        return True
    message = str(exc).lower()
    return any(marker in message for marker in ["timed out", "timeout", "connection reset", "connection aborted", "temporarily unavailable", "service unavailable", "rate limit"])


class NewsLiveConnector:
    def get_bytes(self, url: str, *, timeout: int = 30, headers: dict[str, str] | None = None, attempts: int = 3, base_delay_seconds: float = 1.0, jitter_seconds: float = 0.5, max_delay_seconds: float = 30.0) -> bytes:
        def request_once() -> bytes:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "ai4sec-platform/0.1", **(headers or {})},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - configured trusted sources
                return response.read()

        return retry_call(request_once, attempts=attempts, base_delay_seconds=base_delay_seconds, jitter_seconds=jitter_seconds, max_delay_seconds=max_delay_seconds)


def retry_kwargs(request) -> dict[str, int | float]:
    params = request.params or {}
    config = request.config or {}
    return {
        "attempts": max(1, min(5, int(_configured_value(params, config, "retry_attempts", 3)))),
        "base_delay_seconds": max(0.1, min(30.0, float(_configured_value(params, config, "retry_base_delay_seconds", 1.0)))),
        "jitter_seconds": max(0.0, min(10.0, float(_configured_value(params, config, "retry_jitter_seconds", 0.5)))),
        "max_delay_seconds": max(1.0, min(120.0, float(_configured_value(params, config, "retry_max_delay_seconds", 30.0)))),
    }


def _configured_value(params: dict, config: dict, key: str, default: int | float) -> object:
    if key in params and params[key] is not None:
        return params[key]
    if key in config and config[key] is not None:
        return config[key]
    return default


def _retry_after_seconds(exc: Exception) -> float | None:
    if not isinstance(exc, urllib.error.HTTPError) or exc.code not in {429, 503}:
        return None
    value = exc.headers.get("Retry-After") if exc.headers else None
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
