from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.news_raw import BuildRawNewsDomainItemsStep, ImportAiForSecRawStep, NormalizeAiForSecRawStep


def ai_for_sec_raw_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="news.ai_for_sec_raw_pipeline",
        domain="news",
        steps=[
            ImportAiForSecRawStep(),
            NormalizeAiForSecRawStep(),
            BuildRawNewsDomainItemsStep(),
        ],
    )
