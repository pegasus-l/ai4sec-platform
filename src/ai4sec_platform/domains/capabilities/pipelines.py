from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.capability import AssessCapabilitiesStep, BuildCapabilitiesFromNewsStep


def capability_from_news_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.from_news_pipeline",
        domain="capabilities",
        steps=[BuildCapabilitiesFromNewsStep(), AssessCapabilitiesStep()],
    )
