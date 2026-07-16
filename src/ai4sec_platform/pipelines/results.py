from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StepResult:
    metrics: dict[str, Any] = field(default_factory=dict)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
