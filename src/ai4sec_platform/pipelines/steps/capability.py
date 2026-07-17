from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.adapters.from_news import capability_candidates_from_news
from ai4sec_platform.models.router import LLMRouter
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class BuildCapabilitiesFromNewsStep:
    name: str = "build_capabilities_from_news"
    step_type: str = "build_domain_item"

    def run(self, context: PipelineContext) -> StepResult:
        limit = int(context.params.get("limit", 100))
        existing = repo.list_domain_items(context.conn, "capabilities", limit=limit, status="待能力评估")
        selected = [item["id"] for item in existing[:limit]]
        created: list[int] = []
        if not selected:
            news_items = repo.list_domain_items(context.conn, "news", limit=limit)
            candidates = capability_candidates_from_news(news_items)
            for item in candidates[:limit]:
                payload = item.get("payload") or {}
                capability_id = repo.create_domain_item(
                    context.conn,
                    domain="capabilities",
                    item_type="capability_candidate",
                    title=item.get("title") or payload.get("title") or "未命名能力候选",
                    summary=item.get("summary") or payload.get("summary") or "来自资讯 raw pipeline 的能力候选。",
                    score=None,
                    status="待能力评估",
                    source="news_raw_pipeline",
                    source_url=item.get("source_url") or payload.get("code_url") or payload.get("url") or "",
                    primary_date=item.get("primary_date") or payload.get("primary_date") or "",
                    tags=["能力候选", "from_news", "raw_pipeline"],
                    metrics={"source_news_item_id": item.get("id"), "pipeline_run": context.run_id},
                    payload={"source_news_item": item},
                )
                created.append(capability_id)
            selected = created
        context.outputs["capability_candidate_ids"] = selected
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="capability_candidates", name="capabilities/candidates.json", data={"candidate_ids": selected, "created_ids": created})
        return StepResult(metrics={"candidates": len(selected), "created": len(created), "reused_existing": len(selected) - len(created)}, artifacts=[artifact])


@dataclass
class AssessCapabilitiesStep:
    name: str = "assess_capabilities"
    step_type: str = "llm_review"
    model_profile: str = "configured_model"

    def run(self, context: PipelineContext) -> StepResult:
        ids = context.outputs.get("capability_candidate_ids") or []
        router = LLMRouter()
        assessed = 0
        for item_id in ids:
            item = context.conn.execute("SELECT * FROM domain_items WHERE id = ?", (item_id,)).fetchone()
            if not item:
                continue
            item_data = repo.row_to_dict(item)
            prompt = "评估该论文或项目是否值得复现和能力转化，输出结构化建议。"
            output = router.complete_json(profile=self.model_profile, prompt=prompt, payload=item_data)
            repo.create_model_call(
                context.conn,
                run_id=context.run_id,
                agent_name="capability_assess",
                model_profile=self.model_profile,
                provider=output.get("provider", self.model_profile),
                status="success",
                input_payload={"item": item_data, "prompt": prompt},
                output_payload=output,
            )
            repo.update_domain_item(
                context.conn,
                item_id=item_id,
                status="待复现验证",
                score=item_data.get("score") if item_data.get("score") is not None else 0.5,
                metrics={"assessment_status": "rule_assessed"},
                payload={"assessment": output},
            )
            assessed += 1
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="capability_assessments", name="capabilities/assessments.json", data={"assessed": assessed, "model_profile": self.model_profile})
        repo.create_quality_audit(context.conn, domain="capabilities", audit_type="capability_assessment", status="pass" if assessed else "warn", score=0.8 if assessed else 0.2, summary=f"能力评估 {assessed} 条，当前使用本地规则引擎。", details={"run_id": context.run_id})
        return StepResult(metrics={"assessed": assessed, "model_profile": self.model_profile}, artifacts=[artifact])
