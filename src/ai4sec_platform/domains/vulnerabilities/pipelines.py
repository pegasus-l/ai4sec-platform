from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.vulnerability_discovery import BuildAcceptedVulnerabilityMaterialsStep, CollectAnySearchCandidatesStep, CrawlCandidatePagesStep, ExtractCrawledContentStep, ReviewCrawledMaterialsStep
from ai4sec_platform.pipelines.steps.vulnerability_event import AggregateVulnerabilityEventsStep
from ai4sec_platform.pipelines.steps.vulnerability_evaluation import BuildVulnerabilityShadowEvaluationStep
from ai4sec_platform.pipelines.steps.vulnerability_raw import BuildVulnerabilityMaterialItemsStep, ImportVulnerabilityRawStep, NormalizeVulnerabilityRawStep
from ai4sec_platform.pipelines.steps.vulnerability_knowledge import ExtractVulnerabilityKnowledgeStep, SelectVulnerabilityKnowledgeCandidatesStep


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


def vulnerability_event_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.event_aggregation_pipeline",
        domain="vulnerabilities",
        steps=[AggregateVulnerabilityEventsStep()],
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
            BuildAcceptedVulnerabilityMaterialsStep(),
            AggregateVulnerabilityEventsStep(),
            SelectVulnerabilityKnowledgeCandidatesStep(),
            ExtractVulnerabilityKnowledgeStep(),
            BuildVulnerabilityShadowEvaluationStep(),
        ],
    )
