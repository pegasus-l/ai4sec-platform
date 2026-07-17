from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.threat_asset_import import ImportHuaweiThreatAssetsStep
from ai4sec_platform.pipelines.steps.threat_cve_scout import HuaweiCveScoutStep
from ai4sec_platform.pipelines.steps.threat_report import BuildHuaweiThreatReportStep
from ai4sec_platform.pipelines.steps.threat_score_filter import HuaweiAttackSurfaceScoreStep
from ai4sec_platform.pipelines.steps.threat_raw import BuildHuaweiThreatItemsStep, ImportHuaweiRawStep, NormalizeHuaweiRawStep
from ai4sec_platform.pipelines.steps.threat_risk import ReasonThreatRiskStep, SelectThreatRiskCandidatesStep


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


def huawei_cve_scout_pipeline() -> PipelineDefinition:
    return PipelineDefinition(name="threats.huawei_cve_scout_pipeline", domain="threats", steps=[HuaweiCveScoutStep()])


def huawei_attack_surface_pipeline() -> PipelineDefinition:
    return PipelineDefinition(name="threats.huawei_attack_surface_pipeline", domain="threats", steps=[HuaweiAttackSurfaceScoreStep()])


def huawei_asset_pipeline() -> PipelineDefinition:
    return PipelineDefinition(name="threats.huawei_asset_pipeline", domain="threats", steps=[ImportHuaweiThreatAssetsStep()])


def huawei_full_migration_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="threats.huawei_full_migration_pipeline",
        domain="threats",
        steps=[
            HuaweiCveScoutStep(),
            HuaweiAttackSurfaceScoreStep(),
            ImportHuaweiRawStep(),
            NormalizeHuaweiRawStep(),
            BuildHuaweiThreatItemsStep(),
            ImportHuaweiThreatAssetsStep(),
            SelectThreatRiskCandidatesStep(),
            ReasonThreatRiskStep(),
            BuildHuaweiThreatReportStep(),
        ],
    )
