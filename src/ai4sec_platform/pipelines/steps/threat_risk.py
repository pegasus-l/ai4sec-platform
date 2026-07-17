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
        rows = context.conn.execute(
            """
            SELECT * FROM domain_items
            WHERE domain = 'threats'
              AND item_type = 'target'
              AND status IN ('高风险待研判', '待研判', '持续观察')
            ORDER BY COALESCE(score, 0) DESC, id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        candidates = [repo.row_to_dict(row) for row in rows]
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
    model_profile: str = "configured_model"

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
            prompt = _semantic_review_prompt()
            review_payload = _semantic_review_payload(target)
            output = router.complete_json(profile=self.model_profile, prompt=prompt, payload=review_payload)
            repo.create_model_call(
                context.conn,
                run_id=context.run_id,
                agent_name="risk_reasoning",
                model_profile=self.model_profile,
                provider=output.get("provider", self.model_profile),
                status="success",
                input_payload={"item": review_payload, "prompt": prompt},
                output_payload=output,
            )
            assessment = _build_assessment(target, output)
            score = _score(target)
            semantic = assessment.get("semantic_review") or {}
            status = semantic.get("recommended_tracking_level") or ("高风险跟踪" if score >= 80 else "持续观察" if score >= 50 else "低优先级观察")
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
                metrics={"risk_reasoned": True, "risk_pipeline_run": context.run_id, "semantic_confidence": semantic.get("confidence")},
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
            summary=f"威胁风险研判 {reasoned} 条，高优先级跟踪 {tracked} 条，已通过 configured_model/local_rules 进行语义复核。",
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
    model_result = output.get("result") or output.get("parsed") or {}
    semantic_review = _normalize_semantic_review(model_result)
    return {
        "source_target_id": target.get("id"),
        "risk_score": score,
        "risk_grade": payload.get("risk_grade") or grade,
        "summary": semantic_review.get("summary") or target.get("summary") or f"{target.get('title')} 当前风险等级为{grade}，建议按优先级持续跟踪。",
        "signals": {
            "cve_count": payload.get("cve_count"),
            "sa_count": payload.get("sa_count"),
            "broad_sec_count": payload.get("broad_sec_count"),
            "attack_surface": payload.get("attack_surface"),
            "vulnerability_signals": payload.get("vulnerability_signals"),
            "firmware_refs": payload.get("firmware_refs") or [],
            "mirror_refs": payload.get("mirror_refs") or [],
            "stars": payload.get("stars"),
        },
        "semantic_review": semantic_review,
        "recommended_actions": semantic_review.get("recommended_actions") or ["确认资产归属", "核对 CVE 影响版本", "关注固件与镜像更新", "必要时加入人工跟踪队列"],
        "model_output": output,
    }


def _semantic_review_prompt() -> str:
    return """
你是威胁情报分析员，需要复核华为开源仓库/组件的威胁价值。请只输出 JSON。

你需要基于当前平台 connector 获取到的仓库、issue、安全文件、CVE/SA、固件和镜像线索完成判断：
1. 判断 broad_sec_items / issue 标题是否是真安全问题，还是普通 bug/误报。
2. 解释该项目的主要攻击面，例如 kernel、driver、network protocol、parser/codec、sandbox、security boundary。
3. 根据 CVE/SA、security repo 来源、项目自身 issue、平台攻击面评分和仓库描述，给出漏洞挖掘价值判断。
4. 给出下一步动作：跟踪、人工复核、补充 GitHub 搜索、验证高危 CVE 是否已修复、关注 security 仓库。

输出 JSON schema：
{
  "summary": "一句话风险结论",
  "is_real_security_target": true,
  "valid_security_findings": ["有效安全线索"],
  "false_positive_risks": ["可能误报或普通 bug 的线索"],
  "attack_surface_summary": "主要攻击面解释",
  "vulnerability_hypotheses": ["可能的漏洞研究方向"],
  "recommended_tracking_level": "高风险跟踪|持续观察|低优先级观察",
  "recommended_actions": ["下一步动作"],
  "confidence": 0.0
}
""".strip()


def _semantic_review_payload(target: dict[str, Any]) -> dict[str, Any]:
    payload = target.get("payload") or {}
    signals = payload.get("vulnerability_signals") or {}
    return {
        "id": target.get("id"),
        "title": target.get("title"),
        "summary": target.get("summary"),
        "score": target.get("score"),
        "status": target.get("status"),
        "source_url": target.get("source_url"),
        "attack_surface": payload.get("attack_surface"),
        "scoring": payload.get("scoring"),
        "vulnerability_signals": signals,
        "cves": _compact_list(payload.get("cves") or [], 8),
        "sa_items": _compact_list(payload.get("sa_items") or [], 5),
        "broad_sec_items": _compact_list(payload.get("broad_sec_items") or signals.get("sample_security_items") or [], 8),
        "raw_description": (payload.get("raw") or {}).get("description") if isinstance(payload.get("raw"), dict) else "",
    }


def _normalize_semantic_review(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"summary": "模型未返回结构化研判结果。", "confidence": 0.0}
    result = value.get("result") if isinstance(value.get("result"), dict) else value
    actions = result.get("recommended_actions") or []
    if not isinstance(actions, list):
        actions = [str(actions)]
    return {
        "summary": result.get("summary") or result.get("reason") or "已完成语义复核。",
        "is_real_security_target": bool(result.get("is_real_security_target", True)),
        "valid_security_findings": _as_list(result.get("valid_security_findings")),
        "false_positive_risks": _as_list(result.get("false_positive_risks")),
        "attack_surface_summary": result.get("attack_surface_summary") or "",
        "vulnerability_hypotheses": _as_list(result.get("vulnerability_hypotheses")),
        "recommended_tracking_level": result.get("recommended_tracking_level") or "",
        "recommended_actions": actions,
        "confidence": _safe_confidence(result.get("confidence")),
    }


def _compact_list(items: list[Any], limit: int) -> list[Any]:
    return items[:limit] if isinstance(items, list) else []


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value:
        return [value]
    return []


def _safe_confidence(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(1.0, score))
