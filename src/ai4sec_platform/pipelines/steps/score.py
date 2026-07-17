from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.schemas.scoring import ScoreResult


ScorerFn = Callable[[dict[str, Any]], ScoreResult]


@dataclass
class ScoreStep:
    name: str = "score"
    step_type: str = "score"
    input_key: str = "classified_items"
    output_key: str = "scored_items"
    scorer: ScorerFn | None = None

    def run(self, context: PipelineContext) -> StepResult:
        items = [dict(item) for item in list(context.outputs.get(self.input_key) or []) if isinstance(item, dict)]
        scored: list[dict[str, Any]] = []
        for item in items:
            result = self.scorer(item) if self.scorer else ScoreResult(score=float(item.get("score") or 0), priority="medium")
            item["score"] = result.score
            item["scoring"] = result.as_payload()
            scored.append(item)
        context.outputs[self.output_key] = scored
        average = round(sum(float(item.get("score") or 0) for item in scored) / len(scored), 2) if scored else 0.0
        return StepResult(metrics={"scored": len(scored), "average_score": average, "output_key": self.output_key})
