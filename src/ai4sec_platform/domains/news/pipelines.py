from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.news import AuditNewsStep, BuildNewsDailyReportStep, BuildNewsItemsStep, CollectNewsSourcesStep, DeduplicateNewsStep, EnrichNewsCandidatesStep, ExtractNewsReferencesStep, GateNewsCandidatesStep, NormalizeNewsStep, ResolveNewsLinksStep


def news_pipeline(name: str) -> PipelineDefinition:
    return PipelineDefinition(
        name=name,
        domain="news",
        steps=[
            CollectNewsSourcesStep(),
            ExtractNewsReferencesStep(),
            NormalizeNewsStep(),
            DeduplicateNewsStep(),
            ResolveNewsLinksStep(),
            GateNewsCandidatesStep(),
            EnrichNewsCandidatesStep(),
            BuildNewsItemsStep(),
            BuildNewsDailyReportStep(),
            AuditNewsStep(),
        ],
    )


def news_shadow_collect_pipeline() -> PipelineDefinition:
    return news_pipeline("news.shadow_collect_pipeline")


def news_daily_pipeline() -> PipelineDefinition:
    return news_pipeline("news.daily_pipeline")
