from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class DedupeStep:
    name: str = "dedupe"
    step_type: str = "dedupe"
    note: str = "planned"
    metrics: dict[str, Any] = field(default_factory=dict)

    def run(self, context: PipelineContext) -> StepResult:
        return StepResult(metrics={"status": self.note, **self.metrics})
