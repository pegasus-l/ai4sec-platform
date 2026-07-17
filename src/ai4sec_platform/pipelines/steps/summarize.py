from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class SummarizeStep:
    name: str = "summarize"
    step_type: str = "summarize"
    output_key: str = "summary"

    def run(self, context: PipelineContext) -> StepResult:
        summary = {key: len(value) if isinstance(value, list) else type(value).__name__ for key, value in context.outputs.items()}
        context.outputs[self.output_key] = summary
        return StepResult(metrics=summary)
