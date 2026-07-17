from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.schemas.classification import ClassificationResult


ClassifierFn = Callable[[dict[str, Any]], ClassificationResult]


@dataclass
class ClassifyStep:
    name: str = "classify"
    step_type: str = "classify"
    input_key: str = "deduped_items"
    output_key: str = "classified_items"
    classifier: ClassifierFn | None = None

    def run(self, context: PipelineContext) -> StepResult:
        items = [dict(item) for item in list(context.outputs.get(self.input_key) or []) if isinstance(item, dict)]
        classified: list[dict[str, Any]] = []
        for item in items:
            result = self.classifier(item) if self.classifier else ClassificationResult(category=item.get("source_type") or "unknown", confidence=0.5)
            item["classification"] = result.as_payload()
            classified.append(item)
        context.outputs[self.output_key] = classified
        categories: dict[str, int] = {}
        for item in classified:
            category = item.get("classification", {}).get("category", "unknown")
            categories[category] = categories.get(category, 0) + 1
        return StepResult(metrics={"classified": len(classified), "categories": categories, "output_key": self.output_key})
