from __future__ import annotations

from ai4sec_platform.schemas.sources import SourceHealth


def ok(message: str = "ok") -> SourceHealth:
    return SourceHealth(status="ok", message=message)
