from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class NormalizeStep:
    name: str = "normalize"
    step_type: str = "normalize"
    input_key: str = "selected_items"
    output_key: str = "normalized_items"
    normalizer: Callable[[dict[str, Any]], dict[str, Any]] | None = None

    def run(self, context: PipelineContext) -> StepResult:
        items = list(context.outputs.get(self.input_key) or [])
        normalized = [self.normalizer(item) if self.normalizer else dict(item) for item in items if isinstance(item, dict)]
        context.outputs[self.output_key] = normalized
        return StepResult(metrics={"input": len(items), "normalized": len(normalized), "output_key": self.output_key})
