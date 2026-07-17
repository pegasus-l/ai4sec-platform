from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class DedupeStep:
    name: str = "dedupe"
    step_type: str = "dedupe"
    input_key: str = "normalized_items"
    output_key: str = "deduped_items"
    key_fn: Callable[[dict[str, Any]], str] | None = None

    def run(self, context: PipelineContext) -> StepResult:
        items = [item for item in list(context.outputs.get(self.input_key) or []) if isinstance(item, dict)]
        seen: set[str] = set()
        deduped: list[dict[str, Any]] = []
        for item in items:
            key = self.key_fn(item) if self.key_fn else str(item.get("item_key") or item.get("url") or item.get("source_url") or item.get("title") or repr(item))
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        context.outputs[self.output_key] = deduped
        return StepResult(metrics={"input": len(items), "deduped": len(deduped), "duplicates": len(items) - len(deduped), "output_key": self.output_key})
