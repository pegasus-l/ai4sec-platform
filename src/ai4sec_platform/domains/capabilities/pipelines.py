from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.build_domain_item import BuildDomainItemStep


def capability_assessment_placeholder_pipeline() -> PipelineDefinition:
    return PipelineDefinition(name="capabilities.assessment_placeholder", domain="capabilities", steps=[BuildDomainItemStep(note="planned")])
