"""能力洞察 4 条 pipeline 定义。

1. capabilities.from_news_pipeline（已有）: 从资讯派生能力候选 + 评估
2. capabilities.web_classify_pipeline（新增）: Web 项目批量分类
3. capabilities.repro_pipeline（新增）: 复现候选选择 + 启动 + 报告提取
4. capabilities.conversion_pipeline（新增）: 能力转化记录
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.assessments import classify_batch
from ai4sec_platform.domains.capabilities.builders import build_conversion_record
from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.pipelines.steps.capability import AssessCapabilitiesStep, BuildCapabilitiesFromNewsStep, EnrichCapabilityCandidatesStep
from ai4sec_platform.pipelines.steps.repro import (
    ExtractReproReportsStep,
    SelectReproCandidatesStep,
    StartReproTasksStep,
)


# ============================================================================
# 1. 已有：从资讯派生能力候选 + 评估
# ============================================================================
def capability_from_news_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.from_news_pipeline",
        domain="capabilities",
        steps=[BuildCapabilitiesFromNewsStep(), EnrichCapabilityCandidatesStep(), AssessCapabilitiesStep()],
    )


# ============================================================================
# 2. 新增：Web 项目批量分类
# ============================================================================
@dataclass
class SelectUnclassifiedWebCandidatesStep:
    name: str = "select_unclassified_web"
    step_type: str = "select"

    def run(self, context: PipelineContext) -> StepResult:
        limit = int(context.params.get("classify_limit", 50))
        items = repo.list_domain_items(context.conn, "capabilities", item_type="capability", limit=limit * 3)
        candidates = [
            it for it in items
            if not (it.get("payload") or {}).get("web_classify_ts")
            and (
                (it.get("payload") or {}).get("code_url")
                or "github.com" in (it.get("source_url") or "")
            )
        ][:limit]
        context.outputs["web_classify_candidates"] = candidates
        return StepResult(metrics={"candidates": len(candidates)})


@dataclass
class ClassifyWebCapabilityStep:
    name: str = "classify_web"
    step_type: str = "llm_review"

    def run(self, context: PipelineContext) -> StepResult:
        candidates: list[dict[str, Any]] = context.outputs.get("web_classify_candidates") or []
        limit = int(context.params.get("classify_limit", 50))
        result = classify_batch(context.conn, candidates, limit=limit)
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="web_classify",
            name="capabilities/web_classify.json",
            data=result,
        )
        return StepResult(
            metrics={"classified": result["classified"], "failed": result["failed"]},
            artifacts=[artifact],
        )


def capability_web_classify_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.web_classify_pipeline",
        domain="capabilities",
        steps=[SelectUnclassifiedWebCandidatesStep(), ClassifyWebCapabilityStep()],
    )


# ============================================================================
# 3. 新增：复现 pipeline
# ============================================================================
def capability_repro_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.repro_pipeline",
        domain="capabilities",
        steps=[SelectReproCandidatesStep(), StartReproTasksStep(), ExtractReproReportsStep()],
    )


# ============================================================================
# 4. 新增：能力转化 pipeline
# ============================================================================
@dataclass
class SelectConversionCandidatesStep:
    name: str = "select_conversion_candidates"
    step_type: str = "select"

    def run(self, context: PipelineContext) -> StepResult:
        limit = int(context.params.get("conversion_limit", 20))
        items = repo.list_domain_items(
            context.conn, "capabilities", item_type="capability", limit=limit * 2,
        )
        # 只选完整复现成功且还没转化的；partial 不进入能力转化
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
            record = build_conversion_record(
                item,
                scenario="自动识别可转化能力",
                status="持续观察",
            )
            conv_id = repo.create_domain_item(
                context.conn,
                domain="capabilities",
                item_type="capability_conversion",
                title=record["title"],
                summary=record.get("scenario", ""),
                source="repro_pipeline",
                tags=["能力转化", "持续观察"],
                metrics={"pipeline_run": context.run_id, "capability_id": item["id"]},
                payload=record,
            )
            # 更新原能力卡的 conversion_status
            repo.update_domain_item(
                context.conn,
                item_id=item["id"],
                payload={"conversion_status": "持续观察"},
            )
            created.append(conv_id)
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="conversion_records",
            name="capabilities/conversions.json",
            data={"created": created, "count": len(created)},
        )
        return StepResult(
            metrics={"created": len(created), "conversion_ids": created},
            artifacts=[artifact],
        )


def capability_conversion_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="capabilities.conversion_pipeline",
        domain="capabilities",
        steps=[SelectConversionCandidatesStep(), BuildConversionRecordStep()],
    )
