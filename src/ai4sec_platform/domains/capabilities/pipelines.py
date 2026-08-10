"""能力洞察 Pipeline——从 ASIS 原始数据到能力评估的全流程。
Build→CodeLink+Dedup→RuleFilter→FetchREADME→LLMReview→Store→WebClassify
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.assessments import classify_batch
from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.pipelines.steps.capability_raw import (
    BuildFromRawStep,
    CodeLinkDedupStep,
    RuleFilterStep,
    FetchReadmeStep,
    LLMReviewStep,
    StoreCapabilitiesStep,
)
from ai4sec_platform.pipelines.steps.repro import TriggerReproStep
from ai4sec_platform.domains.capabilities.builders import build_conversion_record


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


# 兼容旧 pipeline 名称
def capability_from_news_pipeline() -> PipelineDefinition:
    """兼容旧名称，指向 from_raw_pipeline 的内容但用旧名字。"""
    return PipelineDefinition(
        name="capabilities.from_news_pipeline",
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


# ─────────────────── WebClassify 步骤 ───────────────────

@dataclass
class SelectUnclassifiedWebCandidatesStep:
    name: str = "select_unclassified_web"
    step_type: str = "select"

    def run(self, context: PipelineContext) -> StepResult:
        ids = context.outputs.get("capability_ids") or []
        limit = int(context.params.get("classify_limit", 50))
        candidates: list[dict[str, Any]] = []
        for item_id in ids:
            item = repo.get_domain_item(context.conn, domain="capabilities", item_id=item_id)
            if not item:
                continue
            payload = item.get("payload") or {}
            if not payload.get("web_classify_ts"):
                candidates.append({"id": item_id, "code_url": payload.get("code_url", ""),
                                   "title": item.get("title", ""), "payload": payload})
            if len(candidates) >= limit:
                break
        context.outputs["web_classify_candidates"] = candidates
        return StepResult(metrics={"candidates": len(candidates)})


@dataclass
class ClassifyWebCapabilityStep:
    name: str = "classify_web_capability"
    step_type: str = "classify"

    def run(self, context: PipelineContext) -> StepResult:
        candidates = context.outputs.get("web_classify_candidates") or []
        if not candidates:
            return StepResult(metrics={"classified": 0})
        results = classify_batch(context.conn, candidates, run_id=context.run_id)
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        for r in results:
            item_id = r.get("id")
            if not item_id:
                continue
            item = repo.get_domain_item(context.conn, domain="capabilities", item_id=item_id)
            if not item:
                continue
            payload = item.get("payload") or {}
            payload["is_web"] = r.get("is_web", False)
            payload["web_framework"] = r.get("framework", "")
            payload["web_classify_ts"] = ts
            repo.update_domain_item(context.conn, item_id=item_id, payload=payload)
        return StepResult(metrics={"classified": len(results)})


# ─────────────────── Repro + Conversion 兼容函数 ───────────────────

def capability_web_classify_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.web_classify_pipeline",
        domain="capabilities",
        steps=[SelectUnclassifiedWebCandidatesStep(), ClassifyWebCapabilityStep()],
    )


def capability_repro_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.repro_pipeline",
        domain="capabilities",
        steps=[TriggerReproStep()],
    )


@dataclass
class SelectConversionCandidatesStep:
    name: str = "select_conversion_candidates"
    step_type: str = "select"

    def run(self, context: PipelineContext) -> StepResult:
        limit = int(context.params.get("conversion_limit", 20))
        items = repo.list_domain_items(context.conn, "capabilities", item_type="capability", limit=limit * 2)
        candidates = [
            it for it in items
            if (it.get("payload") or {}).get("repro_status") == "success"
            and not (it.get("payload") or {}).get("conversion_status", "").startswith(("持续观察", "已转化"))
        ][:limit]
        context.outputs["conversion_candidates"] = candidates
        return StepResult(metrics={"candidates": len(candidates)})


@dataclass
class BuildConversionRecordStep:
    name: str = "build_conversion_record"
    step_type: str = "build_domain_item"

    def run(self, context: PipelineContext) -> StepResult:
        candidates: list[dict[str, Any]] = context.outputs.get("conversion_candidates") or []
        created: list[int] = []
        for item in candidates:
            record = build_conversion_record(item, scenario="自动识别可转化能力", status="持续观察")
            conv_id = repo.create_domain_item(
                context.conn, domain="capabilities", item_type="capability_conversion",
                title=record["title"], summary=record.get("scenario", ""),
                source="repro_pipeline", tags=["能力转化", "持续观察"],
                metrics={"pipeline_run": context.run_id, "capability_id": item["id"]},
                payload=record,
            )
            repo.update_domain_item(context.conn, item_id=item["id"], payload={"conversion_status": "持续观察"})
            created.append(conv_id)
        return StepResult(metrics={"created": len(created), "conversion_ids": created})


def capability_conversion_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.conversion_pipeline",
        domain="capabilities",
        steps=[SelectConversionCandidatesStep(), BuildConversionRecordStep()],
    )
