from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.build_domain_item import BuildDomainItemStep
from ai4sec_platform.pipelines.steps.capability import AssessCapabilitiesStep, BuildCapabilitiesFromNewsStep


def capability_assessment_placeholder_pipeline() -> PipelineDefinition:
    return PipelineDefinition(name="capabilities.assessment_placeholder", domain="capabilities", steps=[BuildDomainItemStep(note="planned")])


def capability_from_news_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.from_news_pipeline",
        domain="capabilities",
        steps=[BuildCapabilitiesFromNewsStep(), AssessCapabilitiesStep()],
    )
