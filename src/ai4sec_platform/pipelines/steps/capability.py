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
            from ai4sec_platform.domains.capabilities.adapters.asis_items_source import ASISItemsSource
            source = ASISItemsSource(context.conn)
            news_items = source.fetch_since()
            candidates = capability_candidates_from_news(news_items, score_threshold=0)
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
                capability_id = repo.create_domain_item(context.conn, 
                    
                    domain="capabilities",
                    item_type="capability_candidate",
                    title=display_theme or item.get("title") or "未命名能力候选",
                    summary=news_summary or one_liner or "能力候选",
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
            prompt = """你是安全能力评估专家。评估这个项目是否值得复现和能力转化。输出 JSON：
{"overview":"一句话说清这个项目是做什么的","security_value":"一段话说明它解决了什么安全问题、为什么重要","reproducibility_assessment":"能不能跑起来？需要什么环境/依赖？有什么坑？","code_quality":"README质量、有没有测试、代码结构如何","application_advice":"适合用在什么场景？怎么集成到团队工作流？","recommended_score":1到5的整数,"score_reason":"给这个分的理由（自然语言段落）","capability_type":"从以下选一个：验证与评估 | 推理与规划 | 工具调用","application_scenarios":["场景1","场景2"]}"""
            try:
                output = router.complete_json(profile=self.model_profile, prompt=prompt, payload=item_data)
            except Exception as exc:
                # 单个候选超时/失败，跳过继续评估下一个
                failed += 1
                repo.create_model_call(
                    
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
                
                run_id=context.run_id,
                agent_name="capability_assess",
                model_profile=self.model_profile,
                provider=output.get("provider", self.model_profile),
                status="success",
                input_payload={"item": item_data, "prompt": prompt},
                output_payload=output,
            )
            repo.update_domain_item(
                
                item_id=item_id,
                status=recommended_status,
                score=float(model_result.get("recommended_score") or scoring.score),
                metrics={"assessment_status": "model_assessed", "score_breakdown": scoring.breakdown, "llm_score": model_result.get("recommended_score")},
                payload={
                    "assessment": output,
                    "capability_scoring": scoring.as_payload(),
                    "capability_type": model_result.get("capability_type", ""),
                    "application_scenarios": model_result.get("application_scenarios", []),
                    "repro_status": model_result.get("repro_status", "candidate" if (item_data.get("payload") or {}).get("code_url") else "no_code"),
                    "conversion_status": model_result.get("conversion_status", "待评估"),
                    "score_reason": model_result.get("score_reason", ""),
                    "overview": model_result.get("overview", ""),
                    "security_value": model_result.get("security_value", ""),
                    "reproducibility_assessment": model_result.get("reproducibility_assessment", ""),
                    "code_quality": model_result.get("code_quality", ""),
                    "application_advice": model_result.get("application_advice", ""),
                    "code_url": (item_data.get("payload") or {}).get("code_url", ""),
                    "source_type": (item_data.get("payload") or {}).get("source_type", ""),
                    "source_news_score": (item_data.get("payload") or {}).get("source_news_score"),
                    "implementation_depth": (item_data.get("payload") or {}).get("implementation_depth") or {
                        "has_real_code": bool(
                            (item_data.get("payload") or {}).get("code_url")
                            or "github.com" in str(item_data.get("source_url") or "")
                        ),
                        "has_tests": bool(model_result.get("has_tests", False)),
                        "has_eval": bool(model_result.get("has_eval", False)),
                        "is_prompt_wrapper": bool(model_result.get("is_prompt_wrapper", False)),
                        "is_thin_mcp_wrapper": bool(model_result.get("is_thin_mcp_wrapper", False)),
                    },
                },
            )
            # 评估完成后将 item_type 从 capability_candidate 改为 capability
            context.conn.execute("UPDATE domain_items SET item_type='capability' WHERE id=?", (item_id,))
            assessed += 1
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="capability_assessments", name="capabilities/assessments.json", data={"assessed": assessed, "failed": failed, "model_profile": self.model_profile})
        repo.create_quality_audit(context.conn, domain="capabilities", audit_type="capability_assessment", status="pass" if assessed else "warn", score=0.8 if assessed else 0.2, summary=f"能力评估 {assessed} 条成功，{failed} 条失败。", details={"run_id": context.run_id})
        return StepResult(metrics={"assessed": assessed, "failed": failed, "model_profile": self.model_profile}, artifacts=[artifact])


class EnrichCapabilityCandidatesStep:
    """复用 news/reviewer 的 enrich_candidates, 用 _review_prompt 生成 work_name/summary_zh/promo_line 等。"""
    name: str = "enrich_capability_candidates"
    step_type: str = "llm_enrich"

    def run(self, context: PipelineContext) -> StepResult:
        from ai4sec_platform.domains.news.reviewer import enrich_candidates
        from pathlib import Path

        # 取所有待评估的候选(status=待能力评估)
        candidates = repo.list_domain_items(context.conn, "capabilities", limit=100000, status="待能力评估")
        if not candidates:
            return StepResult(metrics={"enriched": 0, "failed": 0})

        # enrich_candidates 期望 items 有 item_key/source_type/title/summary/url/code_url/raw 等字段
        # candidates 从 DB 读出的格式是 domain_item, 需要从 payload 取出这些字段
        enriched_items = []
        for c_item in candidates:
            payload = c_item.get("payload") or {}
            raw = payload.get("source_news_item") or {}
            # 合并: 顶层字段 + payload 里的字段
            merged = {
                **c_item,
                "item_key": str(c_item.get("id") or ""),
                "title": c_item.get("title") or raw.get("title") or "",
                "summary": raw.get("summary") or c_item.get("summary") or "",
                "url": raw.get("url") or c_item.get("source_url") or "",
                "code_url": raw.get("code_url") or "",
                "source_type": raw.get("source_type") or "project",
                "primary_date": raw.get("primary_date") or c_item.get("primary_date") or "",
                "stars": raw.get("stars") or 0,
                "raw": {"description": raw.get("summary") or ""},
            }
            enriched_items.append(merged)

        selected, metrics = enrich_candidates(
            context.conn,
            enriched_items,
            run_id=context.run_id,
            project_root=context.settings.project_root,
            model_profile="configured_model",
            min_decision="all",
        )

        # 更新候选: 把 review 结果写到 payload 里
        updated = 0
        for item in selected:
            review = item.get("review") or {}
            if not review:
                continue
            existing = repo.get_domain_item(item["id"])
            if not existing:
                continue
            existing_payload = existing.get("payload") or {}
            existing_payload["review"] = review
            # 用 work_name:theme_descriptor 替换原标题(如果 review 成功)
            work_name = review.get("work_name") or ""
            theme_descriptor = review.get("theme_descriptor") or ""
            theme = review.get("theme") or ""
            if theme:
                existing_payload["display_title"] = theme
            if review.get("summary_zh"):
                existing_payload["display_summary"] = review["summary_zh"]
            if review.get("promo_line"):
                existing_payload["promo_line"] = review["promo_line"]
            if review.get("highlight_line"):
                existing_payload["highlight_line"] = review["highlight_line"]
            existing_payload["review_status"] = "enriched"
            repo.update_domain_item(item_id=item["id"], payload=existing_payload)
            updated += 1
        context.conn.commit()
        return StepResult(metrics={"enriched": updated, "selected": metrics.get("selected", 0), "failed": metrics.get("failed", 0)})
