from __future__ import annotations

import os
from pathlib import Path

from ai4sec_platform.core.config import PROJECT_ROOT


_LOADED = False


def load_env_file(path: Path | None = None, *, override: bool = False) -> dict[str, str]:
    global _LOADED
    env_path = path or PROJECT_ROOT / ".env"
    loaded: dict[str, str] = {}
    if _LOADED and not override:
        return loaded
    if not env_path.exists():
        _LOADED = True
        return loaded
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = _strip_quotes(value.strip())
        if not key:
            continue
        if override or key not in os.environ:
            os.environ[key] = value
            loaded[key] = value
    _LOADED = True
    return loaded


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
