from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class FetchContentStep:
    name: str = "fetch_content"
    step_type: str = "fetch_content"
    input_key: str = "selected_items"
    output_key: str = "content_items"

    def run(self, context: PipelineContext) -> StepResult:
        items = [dict(item) for item in list(context.outputs.get(self.input_key) or []) if isinstance(item, dict)]
        for item in items:
            item["content"] = item.get("content") or item.get("summary") or item.get("title") or ""
        context.outputs[self.output_key] = items
        return StepResult(metrics={"content_items": len(items), "output_key": self.output_key})
