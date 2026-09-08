from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.threat_asset_import import ImportHuaweiThreatAssetsStep
from ai4sec_platform.pipelines.steps.threat_association import AssetAssociationStep
from ai4sec_platform.pipelines.steps.threat_cve_scout import HuaweiCveScoutStep
from ai4sec_platform.pipelines.steps.threat_report import BuildHuaweiThreatReportStep
from ai4sec_platform.pipelines.steps.threat_score_filter import HuaweiAttackSurfaceScoreStep
from ai4sec_platform.pipelines.steps.threat_sources import CollectHuaweiSourcesStep
from ai4sec_platform.pipelines.steps.threat_raw import BuildHuaweiThreatItemsStep, ImportHuaweiRawStep, NormalizeHuaweiRawStep
from ai4sec_platform.pipelines.steps.threat_risk import ReasonThreatRiskStep, SelectThreatRiskCandidatesStep



def huawei_collect_sources_pipeline() -> PipelineDefinition:
    return PipelineDefinition(name="threats.huawei_collect_sources_pipeline", domain="threats", steps=[CollectHuaweiSourcesStep()])


def threat_risk_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="threats.risk_reasoning_pipeline",
        domain="threats",
        steps=[SelectThreatRiskCandidatesStep(), ReasonThreatRiskStep()],
    )


def asset_association_pipeline() -> PipelineDefinition:
    """资产↔代码仓 AI 关联批跑。手动经 POST /api/runs 触发(MVP 不上定时)。"""
    return PipelineDefinition(
        name="threats.asset_association_pipeline",
        domain="threats",
        steps=[AssetAssociationStep()],
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
            CollectHuaweiSourcesStep(),
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
