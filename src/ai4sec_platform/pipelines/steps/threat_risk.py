from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.models.router import LLMRouter
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class SelectThreatRiskCandidatesStep:
    name: str = "select_threat_risk_candidates"
    step_type: str = "select"

    def run(self, context: PipelineContext) -> StepResult:
        limit = int(context.params.get("limit", 50))
        candidates = repo.list_domain_items(context.conn, "threats", item_type="target", limit=limit, status="待研判")
        if not candidates:
            candidates = repo.list_domain_items(context.conn, "threats", item_type="target", limit=limit)
        candidate_ids = [int(item["id"]) for item in candidates[:limit]]
        context.outputs["threat_risk_candidate_ids"] = candidate_ids
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="threat_risk_candidates",
            name="threats/risk_candidates.json",
            data={"candidate_ids": candidate_ids},
        )
        return StepResult(metrics={"candidates": len(candidate_ids)}, artifacts=[artifact])


@dataclass
class ReasonThreatRiskStep:
    name: str = "reason_threat_risk"
    step_type: str = "llm_review"
    model_profile: str = "local_rules"

    def run(self, context: PipelineContext) -> StepResult:
        ids = context.outputs.get("threat_risk_candidate_ids") or []
        router = LLMRouter()
        reasoned = 0
        tracked = 0
        for item_id in ids:
            row = context.conn.execute("SELECT * FROM domain_items WHERE id = ? AND domain = ?", (item_id, "threats")).fetchone()
            if not row:
                continue
            target = repo.row_to_dict(row)
            prompt = "基于目标仓库、CVE、固件、镜像等本地原始线索，判断威胁风险等级、跟踪理由和下一步动作。"
            output = router.complete_json(profile=self.model_profile, prompt=prompt, payload=target)
            repo.create_model_call(
                context.conn,
                run_id=context.run_id,
                agent_name="risk_reasoning",
                model_profile=self.model_profile,
                provider=output.get("provider", "local_rules"),
                status="success",
                input_payload={"item": target, "prompt": prompt},
                output_payload=output,
            )
            assessment = _build_assessment(target, output)
            score = _score(target)
            status = "高风险跟踪" if score >= 80 else "持续观察" if score >= 50 else "低优先级观察"
            repo.create_evidence(
                context.conn,
                domain="threats",
                domain_item_id=item_id,
                evidence_type="risk_assessment",
                title="风险研判结果",
                content=assessment["summary"],
                source_url=target.get("source_url") or "",
                confidence=score / 100 if score else None,
                payload=assessment,
            )
            repo.update_domain_item(
                context.conn,
                item_id=item_id,
                status=status,
                score=score,
                metrics={"risk_reasoned": True, "risk_pipeline_run": context.run_id},
                payload={"risk_assessment": assessment},
            )
            if score >= 80:
                repo.create_human_queue_item(
                    context.conn,
                    domain="threats",
                    item_id=item_id,
                    queue_type="threat_tracking_review",
                    priority=1,
                    reason="风险研判认为该目标需要进入高优先级跟踪。",
                    payload={"run_id": context.run_id, "assessment": assessment},
                )
                tracked += 1
            reasoned += 1
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="threat_risk_assessments",
            name="threats/risk_assessments.json",
            data={"reasoned": reasoned, "tracked": tracked, "model_profile": self.model_profile},
        )
        repo.create_quality_audit(
            context.conn,
            domain="threats",
            audit_type="risk_reasoning",
            status="pass" if reasoned else "warn",
            score=0.8 if reasoned else 0.2,
            summary=f"威胁风险研判 {reasoned} 条，高优先级跟踪 {tracked} 条，当前使用本地规则引擎。",
            details={"run_id": context.run_id},
        )
        return StepResult(metrics={"reasoned": reasoned, "tracked": tracked}, artifacts=[artifact])


def _score(target: dict[str, Any]) -> float:
    if target.get("score") is not None:
        try:
            return float(target["score"])
        except (TypeError, ValueError):
            pass
    payload = target.get("payload") or {}
    try:
        return float(payload.get("risk_score") or 50)
    except (TypeError, ValueError):
        return 50.0


def _build_assessment(target: dict[str, Any], output: dict[str, Any]) -> dict[str, Any]:
    payload = target.get("payload") or {}
    score = _score(target)
    grade = "高" if score >= 80 else "中" if score >= 50 else "低"
    return {
        "source_target_id": target.get("id"),
        "risk_score": score,
        "risk_grade": payload.get("risk_grade") or grade,
        "summary": target.get("summary") or f"{target.get('title')} 当前风险等级为{grade}，建议按优先级持续跟踪。",
        "signals": {
            "cve_count": payload.get("cve_count"),
            "firmware_refs": payload.get("firmware_refs") or [],
            "mirror_refs": payload.get("mirror_refs") or [],
            "stars": payload.get("stars"),
        },
        "recommended_actions": ["确认资产归属", "核对 CVE 影响版本", "关注固件与镜像更新", "必要时加入人工跟踪队列"],
        "model_output": output,
    }
