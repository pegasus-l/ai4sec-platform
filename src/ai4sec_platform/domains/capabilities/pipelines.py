"""能力洞察 Pipeline——从 ASIS 原始数据到能力评估的全流程。
Build→CodeLink+Dedup→RuleFilter→FetchREADME→LLMReview→Store→WebClassify
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.assessments import classify_batch, is_non_web_blocked
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


@dataclass
class ReDemoteDriftedNonWebStep:
    """把"已被判非 web 却又回到待复现验证"的条目重新降级 —— 自我修复, 零 LLM 调用。

    起因(2026-09-15 查实): StoreCapabilitiesStep 按 code_url 复用已有行时会用 review 结论重算
    status, 不看 is_web → 每晚资讯重扫重发现同一 repo 就把已淘汰的条目写回"待复现验证"; 而
    SelectUnclassifiedWebCandidatesStep 只挑没有 web_classify_ts 的条目, 分类过的永不再分类 →
    一旦漂移就再没有机会降级。此步补上这个缺口: 不看 web_classify_ts, 直接按已落库的 is_web
    判据把漂移条目踢出队列。放在 web_classify 之后, 每晚随主 pipeline 一起兜住。
    """
    name: str = "redemote_drifted_non_web"
    step_type: str = "classify"

    def run(self, context: PipelineContext) -> StepResult:
        items = repo.list_domain_items(
            context.conn, "capabilities", item_type="capability",
            status="待复现验证", limit=10000,
        )
        demoted = 0
        for it in items:
            if not is_non_web_blocked(it.get("payload") or {}):
                continue
            repo.update_domain_item(context.conn, item_id=it["id"], status="已淘汰")
            demoted += 1
        if demoted:
            context.conn.commit()
        return StepResult(metrics={"redemoted": demoted, "scanned": len(items)})


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
            ReDemoteDriftedNonWebStep(),
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
            ReDemoteDriftedNonWebStep(),
        ],
    )


# ─────────────────── WebClassify 步骤 ───────────────────

@dataclass
class SelectUnclassifiedWebCandidatesStep:
    name: str = "select_unclassified_web"
    step_type: str = "select"

    def run(self, context: PipelineContext) -> StepResult:
        # 扫全表:所有尚未 web 分类的 capability 条目都进候选(不仅当次 run 新建的),
        # 避免新条目因当次 run 错过 select 窗口而永久漏分类
        limit = int(context.params.get("classify_limit", 50))
        candidates: list[dict[str, Any]] = []
        items = repo.list_domain_items(context.conn, "capabilities", item_type="capability", limit=10000)
        for item in items:
            payload = item.get("payload") or {}
            if not payload.get("web_classify_ts"):
                candidates.append({"id": item["id"], "code_url": payload.get("code_url", ""),
                                   "title": item.get("title", ""), "payload": payload,
                                   "source_url": item.get("source_url", ""),
                                   "source_type": item.get("source", "")})
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
        result = classify_batch(context.conn, candidates)
        return StepResult(metrics={
            "classified": result.get("classified", 0),
            "demoted": result.get("demoted", 0),
        })


# ─────────────────── Repro + Conversion 兼容函数 ───────────────────

def capability_web_classify_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.web_classify_pipeline",
        domain="capabilities",
        steps=[SelectUnclassifiedWebCandidatesStep(), ClassifyWebCapabilityStep(), ReDemoteDriftedNonWebStep()],
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
