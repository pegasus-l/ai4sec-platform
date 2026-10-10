from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.vulnerability_batch import RunBatchedVulnerabilityDiscoveryStep
from ai4sec_platform.pipelines.steps.vulnerability_discovery import BuildAcceptedVulnerabilityMaterialsStep, CollectAnySearchCandidatesStep, CrawlCandidatePagesStep, DrillDownAcceptedMaterialsStep, ExtractCrawledContentStep, ReviewCrawledMaterialsStep
from ai4sec_platform.pipelines.steps.vulnerability_event import AggregateVulnerabilityEventsStep
from ai4sec_platform.pipelines.steps.vulnerability_evaluation import BuildVulnerabilityShadowEvaluationStep
from ai4sec_platform.pipelines.steps.vulnerability_raw import BuildVulnerabilityMaterialItemsStep, ImportVulnerabilityRawStep, NormalizeVulnerabilityRawStep
from ai4sec_platform.pipelines.steps.comprehension_probe import ComprehensionProbeStep
from ai4sec_platform.pipelines.steps.vulnerability_knowledge import ExtractVulnerabilityKnowledgeStep, SelectVulnerabilityKnowledgeCandidatesStep
from ai4sec_platform.pipelines.steps.vulnerability_manual import IngestManualMaterialsStep
from ai4sec_platform.pipelines.steps.vulnerability_pattern import SynthesizeVulnerabilityPatternsStep


def vulnerability_raw_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.material_raw_pipeline",
        domain="vulnerabilities",
        steps=[ImportVulnerabilityRawStep(), NormalizeVulnerabilityRawStep(), BuildVulnerabilityMaterialItemsStep()],
    )


def vulnerability_knowledge_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.knowledge_extraction_pipeline",
        domain="vulnerabilities",
        steps=[SelectVulnerabilityKnowledgeCandidatesStep(), ExtractVulnerabilityKnowledgeStep()],
    )


def vulnerability_manual_ingest_pipeline() -> PipelineDefinition:
    """人工投喂 URL / 文章 → 素材 → 知识候选(2026-10-10)。

    只挂三步:入库 → 选候选 → 抽知识。把 Select/Extract 也挂上,是为了让用户投喂完
    **当场**看到结果 —— Select 会走"只取本 run 刚建的那几个 id"的分支,投喂的素材立刻
    变成知识候选 + 人工复核队列行,不用干等到当晚 22:00 的跑批。

    启动方(API)会显式传 `pending_drain_limit: 0`:兜底排空是给**定时跑批**用的,
    用户喂一条 URL 却连带把 20 条无关积压也抽一遍,既费模型又让人看不懂在跑什么。
    """
    return PipelineDefinition(
        name="vulnerabilities.manual_material_ingest_pipeline",
        domain="vulnerabilities",
        steps=[IngestManualMaterialsStep(), SelectVulnerabilityKnowledgeCandidatesStep(), ExtractVulnerabilityKnowledgeStep()],
    )


def comprehension_probe_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.comprehension_probe_pipeline",
        domain="vulnerabilities",
        steps=[ComprehensionProbeStep()],
    )


def vulnerability_event_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.event_aggregation_pipeline",
        domain="vulnerabilities",
        steps=[AggregateVulnerabilityEventsStep()],
    )


def vulnerability_pattern_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.pattern_synthesis_pipeline",
        domain="vulnerabilities",
        steps=[SynthesizeVulnerabilityPatternsStep()],
    )


def vulnerability_external_discovery_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.external_material_discovery_pipeline",
        domain="vulnerabilities",
        steps=[
            CollectAnySearchCandidatesStep(),
            CrawlCandidatePagesStep(),
            ExtractCrawledContentStep(),
            ReviewCrawledMaterialsStep(),
            DrillDownAcceptedMaterialsStep(),
            BuildAcceptedVulnerabilityMaterialsStep(),
            BuildVulnerabilityShadowEvaluationStep(),
        ],
    )


def vulnerability_full_discovery_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.full_knowledge_discovery_pipeline",
        domain="vulnerabilities",
        steps=[
            CollectAnySearchCandidatesStep(),
            CrawlCandidatePagesStep(),
            ExtractCrawledContentStep(),
            ReviewCrawledMaterialsStep(),
            DrillDownAcceptedMaterialsStep(),
            BuildAcceptedVulnerabilityMaterialsStep(),
            AggregateVulnerabilityEventsStep(),
            SelectVulnerabilityKnowledgeCandidatesStep(),
            ExtractVulnerabilityKnowledgeStep(),
            BuildVulnerabilityShadowEvaluationStep(),
        ],
    )


def vulnerability_batched_full_discovery_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.batched_full_knowledge_discovery_pipeline",
        domain="vulnerabilities",
        steps=[RunBatchedVulnerabilityDiscoveryStep()],
    )
