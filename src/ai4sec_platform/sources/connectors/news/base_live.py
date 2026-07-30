from __future__ import annotations

import random
import socket
import time
from collections.abc import Callable
from typing import TypeVar
import urllib.error
import urllib.request

ResultType = TypeVar("ResultType")


def retry_call(operation: Callable[[], ResultType], *, attempts: int = 3, base_delay_seconds: float = 1.0, jitter_seconds: float = 0.5) -> ResultType:
    last_error: Exception | None = None
    for attempt in range(1, max(1, attempts) + 1):
        try:
            return operation()
        except Exception as exc:
            last_error = exc
            if attempt >= attempts or not is_retryable_source_error(exc):
                raise
            delay = base_delay_seconds * (2 ** (attempt - 1)) + random.uniform(0, jitter_seconds)
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
    def get_bytes(self, url: str, *, timeout: int = 30, headers: dict[str, str] | None = None, attempts: int = 3) -> bytes:
        def request_once() -> bytes:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "ai4sec-platform/0.1", **(headers or {})},
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - configured trusted sources
                return response.read()

        return retry_call(request_once, attempts=attempts)
