from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from typing import Any, Callable

from ai4sec_platform.artifacts.store import ArtifactStore
from ai4sec_platform.core.config import Settings


@dataclass
class PipelineContext:
    run_id: str
    pipeline_name: str
    domain: str
    settings: Settings
    conn: sqlite3.Connection
    artifact_store: ArtifactStore
    params: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    should_cancel: Callable[[], bool] = field(default=lambda: False, repr=False)
