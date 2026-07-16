from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.import_existing import ImportLegacySamplesStep
from ai4sec_platform.pipelines.steps.vulnerability_raw import BuildVulnerabilityMaterialItemsStep, ImportVulnerabilityRawStep, NormalizeVulnerabilityRawStep


def material_snapshot_import_pipeline() -> PipelineDefinition:
    return PipelineDefinition(name="vulnerabilities.material_snapshot_import", domain="vulnerabilities", steps=[ImportLegacySamplesStep()])


def vulnerability_raw_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.material_raw_pipeline",
        domain="vulnerabilities",
        steps=[ImportVulnerabilityRawStep(), NormalizeVulnerabilityRawStep(), BuildVulnerabilityMaterialItemsStep()],
    )
