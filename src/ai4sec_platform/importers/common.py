from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"exists": False, "path": str(path)}
    return {"exists": True, "path": str(path), "bytes": path.stat().st_size, "sha256": file_sha256(path)}


def as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def text_excerpt(value: Any, limit: int = 420) -> str:
    text = ""
    if isinstance(value, str):
        text = value
    elif value is not None:
        text = str(value)
    text = " ".join(text.split())
    return text[:limit]


def clean_tags(*values: Any) -> list[str]:
    tags: list[str] = []
    for value in values:
        if isinstance(value, list):
            candidates = value
        elif isinstance(value, str):
            candidates = [value]
        else:
            candidates = []
        for candidate in candidates:
            text = str(candidate).strip()
            if text and text not in tags:
                tags.append(text)
    return tags[:12]
