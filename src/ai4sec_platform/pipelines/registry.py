from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.domains.capabilities.pipelines import capability_assessment_placeholder_pipeline
from ai4sec_platform.domains.news.pipelines import ai_for_sec_raw_pipeline, ai_for_sec_shadow_import_pipeline
from ai4sec_platform.domains.threats.pipelines import huawei_raw_pipeline, huawei_snapshot_import_pipeline
from ai4sec_platform.domains.vulnerabilities.pipelines import material_snapshot_import_pipeline, vulnerability_raw_pipeline
from ai4sec_platform.pipelines.steps.import_existing import ImportLegacySamplesStep


class PipelineRegistry:
    def __init__(self) -> None:
        self._pipelines: dict[str, PipelineDefinition] = {}

    def register(self, definition: PipelineDefinition) -> None:
        self._pipelines[definition.name] = definition

    def get(self, name: str) -> PipelineDefinition:
        try:
            return self._pipelines[name]
        except KeyError as exc:
            raise ValueError(f"Unknown pipeline: {name}") from exc

    def list(self) -> list[dict[str, str]]:
        return [{"name": item.name, "domain": item.domain, "steps": str(len(item.steps))} for item in self._pipelines.values()]


def default_registry() -> PipelineRegistry:
    registry = PipelineRegistry()
    registry.register(
        PipelineDefinition(
            name="legacy.sample_import",
            domain="operations",
            steps=[ImportLegacySamplesStep()],
        )
    )
    registry.register(ai_for_sec_shadow_import_pipeline())
    registry.register(ai_for_sec_raw_pipeline())
    registry.register(capability_assessment_placeholder_pipeline())
    registry.register(huawei_snapshot_import_pipeline())
    registry.register(huawei_raw_pipeline())
    registry.register(material_snapshot_import_pipeline())
    registry.register(vulnerability_raw_pipeline())
    return registry
