"""能力洞察 Pipeline——从 ASIS 原始数据到能力评估的全流程。
Build→CodeLink+Dedup→RuleFilter→FetchREADME→LLMReview→Store→WebClassify
"""
from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.capability_raw import (
    BuildFromRawStep,
    CodeLinkDedupStep,
    RuleFilterStep,
    FetchReadmeStep,
    LLMReviewStep,
    StoreCapabilitiesStep,
)
from ai4sec_platform.pipelines.steps.capability import (
    SelectUnclassifiedWebCandidatesStep,
    ClassifyWebCapabilityStep,
)


def capability_from_raw_pipeline() -> PipelineDefinition:
    """新能力洞察 Pipeline：从 ASIS 原始数据开始，自打分自评审。"""
    return PipelineDefinition(
        name="capabilities.from_raw_pipeline",
        domain="capabilities",
        steps=[
            BuildFromRawStep(),
            CodeLinkDedupStep(),
            RuleFilterStep(),
            FetchReadmeStep(),
            LLMReviewStep(),
            StoreCapabilitiesStep(),
            SelectUnclassifiedWebCandidatesStep(),
            ClassifyWebCapabilityStep(),
        ],
    )


# 保留旧 pipeline 名称兼容（指向新的 from_raw_pipeline）
def capability_from_news_pipeline() -> PipelineDefinition:
    """兼容旧名称，内部指向 from_raw_pipeline。"""
    pipe = capability_from_raw_pipeline()
    pipe.name = "capabilities.from_news_pipeline"
    return pipe
