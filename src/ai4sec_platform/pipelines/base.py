from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


class PipelineStep(Protocol):
    name: str
    step_type: str

    def run(self, context: PipelineContext) -> StepResult:
        ...


@dataclass(frozen=True)
class PipelineDefinition:
    name: str
    domain: str
    steps: list[PipelineStep]
    idempotency_param: str = ""
