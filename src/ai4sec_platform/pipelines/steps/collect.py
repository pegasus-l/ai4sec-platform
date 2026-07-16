from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.registry import SourceRegistry


@dataclass
class CollectStep:
    connector_name: str
    source_name: str
    name: str = "collect"
    step_type: str = "collect"

    def run(self, context: PipelineContext) -> StepResult:
        connector = SourceRegistry().get(self.connector_name)
        result = connector.fetch(SourceFetchRequest(source_name=self.source_name, params=context.params))
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type=f"source_{self.connector_name}",
            name=f"sources/{self.connector_name}.json",
            data=result.model_dump(),
        )
        return StepResult(metrics={"items": len(result.items), "errors": len(result.errors)}, artifacts=[artifact])
