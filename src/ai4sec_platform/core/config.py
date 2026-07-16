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
    production_writes: bool = False
    live_source_fetch_enabled: bool = False
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
    return Settings(
        project_root=root,
        output_dir=output_dir,
        database_path=database_path,
        production_writes=bool(app.get("production_writes", False)),
        live_source_fetch_enabled=bool(app.get("live_source_fetch_enabled", False)),
        legacy_sources=dict(data.get("legacy_sources", {})),
        import_limits=dict(data.get("import_limits", {})),
    )
