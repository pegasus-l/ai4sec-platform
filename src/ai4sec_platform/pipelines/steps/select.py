from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class SelectStep:
    name: str = "select"
    step_type: str = "select"
    input_key: str = "items"
    output_key: str = "selected_items"
    limit_param: str = "limit"
    default_limit: int = 100

    def run(self, context: PipelineContext) -> StepResult:
        items = list(context.outputs.get(self.input_key) or [])
        limit = int(context.params.get(self.limit_param, self.default_limit))
        selected = items[:limit]
        context.outputs[self.output_key] = selected
        return StepResult(metrics={"input": len(items), "selected": len(selected), "output_key": self.output_key})
