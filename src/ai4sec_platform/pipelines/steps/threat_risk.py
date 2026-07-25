from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
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
        limit = int(context.params.get("risk_review_limit", context.params.get("review_limit", 5)))
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
            # Also write ai_calibration so frontend + summary mode can find calibrated surface
            ai_cal_payload = {
                "risk_assessment": assessment,
                "ai_calibration": {
                    "calibrated_surface": semantic.get("calibrated_surface", ""),
                    "calibrated_score": semantic.get("calibrated_score"),
                    "calibrated_attack_surface": semantic.get("attack_surface_calibration", ""),
                    "score_assessment": semantic.get("rule_score_assessment", ""),
                    "hypotheses": semantic.get("hypotheses", []),
                    "cve_priority": semantic.get("cve_priority", []),
                    "false_positives": semantic.get("false_positives", []),
                    "reviewed_at": datetime.now().isoformat(),
                },
            }
            repo.update_domain_item(
                context.conn,
                item_id=item_id,
                status=status,
                score=score,
                metrics={"risk_reasoned": True, "risk_pipeline_run": context.run_id, "semantic_confidence": semantic.get("confidence")},
                payload=ai_cal_payload,
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
你是漏洞挖掘专家。payload 里有仓库的攻击面评分数据（attack_surface）和 CVE 列表（cves）。

请做 3 件事：

1. 攻击面校准：payload 的 attack_surface.primary_attack_surface 是规则关键词匹配出的攻击面，score/grade 是规则评分。你看仓库描述和 CVE 数据，判断规则评分的攻击面分类是否准确。如果不准，给出正确分类和原因。

2. CVE 优先级筛选：从 payload 的 cves 列表里，筛选最值得深挖的 3-5 个，说明理由。同时指出哪些可能是误报或低价值。

3. 挖洞建议：给出 2-3 个具体的漏洞研究方向。不要泛泛说"建议跟踪"或"建议人工复核"，要具体到"从哪个模块/功能/接口入手，可能的漏洞类型是什么"。

输出 JSON：
{
  "calibrated_surface": "从以下选项中选择一个：kernel / network protocol / database / driver / parser/codec / exec/permission / sandbox / wireless / peripheral / media / browser engine / unknown",
  "calibrated_score": 75,
  "attack_surface_calibration": "规则说 XX，实际应该是 YY，因为...",
  "rule_score_assessment": "规则评分偏高/偏低/合理，因为...",
  "cve_priority": [{"cve_id": "CVE-xxx", "value": "high|medium|low", "reason": "..."}],
  "false_positives": ["CVE-yyy 可能是误报因为..."],
  "hypotheses": ["具体挖洞方向1", "具体挖洞方向2"],
  "summary": "一句话风险总结",
  "confidence": 0.8
}
""".strip()


def _semantic_review_payload(target: dict[str, Any]) -> dict[str, Any]:
    payload = target.get("payload") or {}
    signals = payload.get("vulnerability_signals") or {}
    attack_surface = payload.get("attack_surface") or {}
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    cves = payload.get("cves") or []
    # Send up to 20 CVEs with full description (not truncated to 8)
    cves_full = [
        {"cve_id": c.get("cve_id"), "severity": c.get("severity"), "description": str(c.get("description", ""))[:300]}
        for c in cves[:20] if isinstance(c, dict)
    ]
    broad_sec = payload.get("broad_sec_items") or signals.get("sample_security_items") or []
    broad_sec_full = [
        {"description": str(b.get("description", ""))[:200], "severity": b.get("severity")}
        for b in broad_sec[:15] if isinstance(b, dict)
    ]
    return {
        "id": target.get("id"),
        "title": target.get("title"),
        "summary": target.get("summary"),
        "score": target.get("score"),
        "source_url": target.get("source_url"),
        "repo_description": raw.get("description") or "",
        "repo_name": raw.get("name") or "",
        "repo_org": raw.get("org") or "",
        "stars": raw.get("star_count") or raw.get("stars") or 0,
        "attack_surface": {
            "score": attack_surface.get("score"),
            "grade": attack_surface.get("grade"),
            "primary_attack_surface": (attack_surface.get("signals") or {}).get("primary_attack_surface") if isinstance(attack_surface.get("signals"), dict) else "",
            "reasons": attack_surface.get("reasons") or [],
            "breakdown": attack_surface.get("breakdown") or {},
        },
        "cve_count": payload.get("cve_count") or len(cves),
        "cves": cves_full,
        "broad_sec_items": broad_sec_full,
        "sa_count": payload.get("sa_count") or 0,
    }


def _normalize_semantic_review(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"summary": "模型未返回结构化研判结果。", "confidence": 0.0}
    result: dict[str, Any] = value.get("result") if isinstance(value.get("result"), dict) else value
    if not isinstance(result, dict):
        result = {}
    return {
        "summary": result.get("summary") or "已完成语义复核。",
        "calibrated_surface": result.get("calibrated_surface") or "",
        "calibrated_score": result.get("calibrated_score"),
        "attack_surface_calibration": result.get("attack_surface_calibration") or "",
        "rule_score_assessment": result.get("rule_score_assessment") or "",
        "cve_priority": result.get("cve_priority") if isinstance(result.get("cve_priority"), list) else [],
        "false_positives": _as_list(result.get("false_positives")),
        "hypotheses": _as_list(result.get("hypotheses")),
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
