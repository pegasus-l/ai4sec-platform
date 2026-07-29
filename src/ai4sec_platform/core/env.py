from __future__ import annotations

import os
from pathlib import Path

_LOADED_PATHS: set[Path] = set()


def load_env_file(path: Path | None = None, *, override: bool = False) -> dict[str, str]:
    env_path = (path or Path(__file__).resolve().parents[3] / ".env").resolve()
    loaded: dict[str, str] = {}
    if env_path in _LOADED_PATHS and not override:
        return loaded
    if not env_path.exists():
        _LOADED_PATHS.add(env_path)
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
    _LOADED_PATHS.add(env_path)
    return loaded


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value
