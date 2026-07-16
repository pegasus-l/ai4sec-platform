from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.import_existing import ImportLegacySamplesStep
from ai4sec_platform.pipelines.steps.threat_raw import BuildHuaweiThreatItemsStep, ImportHuaweiRawStep, NormalizeHuaweiRawStep
from ai4sec_platform.pipelines.steps.threat_risk import ReasonThreatRiskStep, SelectThreatRiskCandidatesStep


def huawei_snapshot_import_pipeline() -> PipelineDefinition:
    return PipelineDefinition(name="threats.huawei_snapshot_import", domain="threats", steps=[ImportLegacySamplesStep()])


def huawei_raw_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="threats.huawei_raw_pipeline",
        domain="threats",
        steps=[ImportHuaweiRawStep(), NormalizeHuaweiRawStep(), BuildHuaweiThreatItemsStep()],
    )


def threat_risk_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="threats.risk_reasoning_pipeline",
        domain="threats",
        steps=[SelectThreatRiskCandidatesStep(), ReasonThreatRiskStep()],
    )
