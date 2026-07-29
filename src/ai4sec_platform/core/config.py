from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel


PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseModel):
    project_root: Path
    output_dir: Path
    database_path: Path
    sqlite_busy_timeout_ms: int = 30_000
    sqlite_synchronous: str = "NORMAL"
    production_writes: bool = False
    legacy_sources: dict[str, str] = {}
    import_limits: dict[str, int] = {}


def load_settings(project_root: Path | None = None) -> Settings:
    root = project_root or PROJECT_ROOT
    config_path = root / "configs" / "app.yaml"
    data: dict[str, Any] = {}
    if config_path.exists():
        data = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    paths = data.get("paths", {})
    app = data.get("app", {})
    output_dir = Path(os.getenv("AI4SEC_OUTPUT_DIR", paths.get("output_dir", "output")))
    if not output_dir.is_absolute():
        output_dir = root / output_dir
    database_path = Path(os.getenv("AI4SEC_DATABASE_PATH", paths.get("database_path", "output/ai4sec_platform.db")))
    if not database_path.is_absolute():
        database_path = root / database_path
    sqlite_busy_timeout_ms = _positive_int(os.getenv("AI4SEC_SQLITE_BUSY_TIMEOUT_MS", "30000"), 30_000)
    sqlite_synchronous = os.getenv("AI4SEC_SQLITE_SYNCHRONOUS", "NORMAL").strip().upper()
    if sqlite_synchronous not in {"OFF", "NORMAL", "FULL", "EXTRA"}:
        sqlite_synchronous = "NORMAL"
    return Settings(
        project_root=root,
        output_dir=output_dir,
        database_path=database_path,
        sqlite_busy_timeout_ms=sqlite_busy_timeout_ms,
        sqlite_synchronous=sqlite_synchronous,
        production_writes=bool(app.get("production_writes", False)),
        legacy_sources=dict(data.get("legacy_sources", {})),
        import_limits=dict(data.get("import_limits", {})),
    )


def _positive_int(value: str, default: int) -> int:
    try:
        parsed = int(value)
    except ValueError:
        return default
    return parsed if parsed > 0 else default
