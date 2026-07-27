from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.adapters.from_news import capability_candidates_from_news
from ai4sec_platform.domains.capabilities.scorers import score_capability_candidate
from ai4sec_platform.models.router import LLMRouter
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class BuildCapabilitiesFromNewsStep:
    name: str = "build_capabilities_from_news"
    step_type: str = "build_domain_item"

    def run(self, context: PipelineContext) -> StepResult:
        limit = int(context.params.get("limit", 100000))
        existing = repo.list_domain_items(context.conn, "capabilities", limit=limit, status="待能力评估")
        selected = [item["id"] for item in existing[:limit]]
        created: list[int] = []
        if not selected:
            news_items = repo.list_domain_items(context.conn, "news", limit=limit)
            candidates = capability_candidates_from_news(news_items)
            for item in candidates[:limit]:
                payload = item.get("payload") or {}
                # 从 source_news_item 提取资讯洞察的展示字段
                sni = item.get("source_news_item", {})
                np = sni.get("payload", {}) if isinstance(sni, dict) else {}
                display_theme = np.get("display_theme", "")
                display_topic = np.get("display_topic", "")
                display_work_name = np.get("display_work_name", "")
                one_liner = np.get("one_liner", "")
                highlight = np.get("highlight", "")
                news_summary = np.get("summary", "") or sni.get("summary", "")
                tech_points = np.get("technical_points", [])
                capability_id = repo.create_domain_item(
                    context.conn,
                    domain="capabilities",
                    item_type="capability_candidate",
                    title=display_theme or item.get("title") or "未命名能力候选",
                    summary=one_liner or news_summary or "能力候选",
                    score=None,
                    status="待能力评估",
                    source="news_pipeline",
                    source_url=item.get("source_url") or payload.get("code_url") or payload.get("url") or "",
                    primary_date=item.get("primary_date") or payload.get("primary_date") or "",
                    tags=["能力候选", "from_news", "raw_pipeline"],
                    metrics={"source_news_item_id": item.get("id"), "pipeline_run": context.run_id},
                    payload={
                        "source_news_item": item,
                        "display_theme": display_theme,
                        "display_topic": display_topic,
                        "display_work_name": display_work_name,
                        "one_liner": one_liner,
                        "highlight": highlight,
                        "summary": news_summary,
                        "tech_points": tech_points,
                        "code_url": item.get("code_url", ""),
                        "source_type": item.get("source_type", ""),
                        "source_news_score": item.get("source_news_score"),
                    },
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
        failed = 0
        for item_id in ids:
            item = context.conn.execute("SELECT * FROM domain_items WHERE id = ?", (item_id,)).fetchone()
            if not item:
                continue
            item_data = repo.row_to_dict(item)
            prompt = """评估该论文或项目是否值得复现和能力转化，输出 JSON：
{"recommended_status":"待复现验证或待资料补齐","capability_type":"验证与评估或推理与规划或工具调用","sub_type":"具体子类型","application_scenarios":["场景1","场景2"],"implementation_depth":{"has_real_code":true,"has_tests":false,"has_eval":false},"repro_status":"candidate或no_code","conversion_status":"待评估","summary":"一句话结论","reason":"评估理由"}"""
            try:
                output = router.complete_json(profile=self.model_profile, prompt=prompt, payload=item_data)
            except Exception as exc:
                # 单个候选超时/失败，跳过继续评估下一个
                failed += 1
                repo.create_model_call(
                    context.conn,
                    run_id=context.run_id,
                    agent_name="capability_assess",
                    model_profile=self.model_profile,
                    provider=self.model_profile,
                    status="failed",
                    error_message=str(exc)[:500],
                    input_payload={"item_id": item_id, "title": item_data.get("title", "")},
                    output_payload={},
                )
                continue
            scoring = score_capability_candidate(item_data)
            model_result = output.get("result") or output.get("parsed") or {}
            recommended_status = model_result.get("recommended_status") or ("待复现验证" if scoring.priority in {"high", "medium"} else "待资料补齐")
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
                status=recommended_status,
                score=scoring.score,
                metrics={"assessment_status": "model_assessed", "score_breakdown": scoring.breakdown},
                payload={
                    "assessment": output,
                    "capability_scoring": scoring.as_payload(),
                    "capability_type": model_result.get("capability_type", ""),
                    "sub_type": model_result.get("sub_type", ""),
                    "application_scenarios": model_result.get("application_scenarios", []),
                    "implementation_depth": model_result.get("implementation_depth", {}),
                    "repro_status": model_result.get("repro_status", "candidate" if (item_data.get("payload") or {}).get("code_url") else "no_code"),
                    "conversion_status": model_result.get("conversion_status", "待评估"),
                    "code_url": (item_data.get("payload") or {}).get("code_url", ""),
                    "source_type": (item_data.get("payload") or {}).get("source_type", ""),
                    "source_news_score": (item_data.get("payload") or {}).get("source_news_score"),
                },
            )
            # 评估完成后将 item_type 从 capability_candidate 改为 capability
            context.conn.execute("UPDATE domain_items SET item_type='capability' WHERE id=?", (item_id,))
            assessed += 1
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="capability_assessments", name="capabilities/assessments.json", data={"assessed": assessed, "failed": failed, "model_profile": self.model_profile})
        repo.create_quality_audit(context.conn, domain="capabilities", audit_type="capability_assessment", status="pass" if assessed else "warn", score=0.8 if assessed else 0.2, summary=f"能力评估 {assessed} 条成功，{failed} 条失败。", details={"run_id": context.run_id})
        return StepResult(metrics={"assessed": assessed, "failed": failed, "model_profile": self.model_profile}, artifacts=[artifact])
