from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class RenderStep:
    name: str = "render"
    step_type: str = "render"
    input_key: str = "domain_item_ids"
    artifact_name: str = "render/output.json"

    def run(self, context: PipelineContext) -> StepResult:
        payload = {"run_id": context.run_id, "pipeline_name": context.pipeline_name, "domain": context.domain, "items": context.outputs.get(self.input_key) or []}
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="render", name=self.artifact_name, data=payload)
        return StepResult(metrics={"rendered": len(payload["items"])}, artifacts=[artifact])
