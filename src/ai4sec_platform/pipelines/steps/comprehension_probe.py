from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.vulnerabilities.bounded_parallel import model_circuit_failure_threshold, model_max_concurrency, run_bounded_with_circuit
from ai4sec_platform.domains.vulnerabilities.comprehension_probers import (
    build_probe_payload,
    probe_knowledge,
)
from ai4sec_platform.domains.vulnerabilities.model_inputs import prepare_model_input
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class ComprehensionProbeStep:
    """可理解性验证闭环：新 LLM 只读素材作答，judge LLM 与知识标准字段对拍判分。

    - 对每条知识回溯其原始素材正文，喂给"只读素材作答"的 LLM
    - judge LLM 把作答与知识条目的标准字段逐项比对打分
    - 低于阈值（整体<0.7 / 弱字段<0.5）标记可理解性不足
    - 按 knowledge_id 幂等 upsert probe 条目，并把 verification 合并写回知识条目
    - aggregate_feedback 产出的回灌建议落到 quality audit
    """
    name: str = "comprehension_probe"
    step_type: str = "llm_review"
    model_profile: str = "configured_model"

    def run(self, context: PipelineContext) -> StepResult:
        limit = int(context.params.get("limit", 50))
        rows = context.conn.execute(
            "SELECT * FROM domain_items WHERE domain = ? AND item_type = ? ORDER BY score DESC, id DESC LIMIT ?",
            ("vulnerabilities", "knowledge", limit),
        ).fetchall()
        items = [repo.row_to_dict(row) for row in rows]
        jobs: list[tuple[dict[str, Any], str]] = []
        for item in items:
            material_text = _load_material_text(context, item)
            prepared, _ = prepare_model_input(material_text, profile="vulnerability_comprehension_prober")
            jobs.append((item, prepared))

        max_concurrency = model_max_concurrency(context.params)
        circuit_failure_threshold = model_circuit_failure_threshold(context.params, max_concurrency)
        parallel = run_bounded_with_circuit(
            jobs,
            worker=lambda job: probe_knowledge(job[0], job[1], use_model=True),
            fallback_worker=lambda job: probe_knowledge(job[0], job[1], use_model=False),
            is_failure=lambda output: bool((output.get("result") or {}).get("llm_error")),
            max_concurrency=max_concurrency,
            circuit_failure_threshold=circuit_failure_threshold,
        )

        probe_ids: list[int] = []
        probe_payloads: list[dict[str, Any]] = []
        passed = 0
        for job, output in zip(jobs, parallel.items):
            knowledge_item, material_text = job
            probe_payload = build_probe_payload(knowledge_item, material_text, output)
            probe_id = _upsert_probe(context, knowledge_item, probe_payload)
            if probe_id is None:
                continue
            probe_ids.append(probe_id)
            probe_payloads.append(probe_payload)
            if probe_payload["verdict"] == "pass":
                passed += 1
            # 写回知识条目 verification（merge，不覆盖其它字段）
            repo.update_domain_item(
                context.conn,
                item_id=knowledge_item["id"],
                payload={
                    "verification": {
                        "overall_score": probe_payload["overall_score"],
                        "verdict": probe_payload["verdict"],
                        "weak_fields": probe_payload["weak_fields"],
                        "probe_id": probe_payload["probe_id"],
                    }
                },
            )
            repo.create_evidence(
                context.conn,
                domain="vulnerabilities",
                domain_item_id=knowledge_item["id"],
                evidence_type="comprehension_probe",
                title="可理解性验证结果",
                content=f"整体 {probe_payload['overall_score']} · {probe_payload['verdict']} · 弱维度 {', '.join(probe_payload['weak_fields']) or '无'}",
                source_url="",
                confidence=probe_payload["overall_score"],
                payload={
                    "probe_id": probe_payload["probe_id"],
                    "per_field_scores": probe_payload["per_field_scores"],
                    "model_output": output,
                },
            )

        aggregate = _aggregate_summary(probe_payloads)
        avg_score = round(sum(p["overall_score"] for p in probe_payloads) / max(len(probe_payloads), 1), 2)
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="vulnerability_comprehension",
            name="vulnerabilities/comprehension.json",
            data={
                "tested": len(jobs),
                "passed": passed,
                "failed": len(jobs) - passed,
                "avg_score": avg_score,
                "probe_ids": probe_ids,
                "aggregate_feedback": aggregate,
            },
        )
        repo.create_quality_audit(
            context.conn,
            domain="vulnerabilities",
            audit_type="comprehension_probe",
            status="pass" if passed >= len(jobs) * 0.7 else "warn",
            score=avg_score,
            summary=f"可理解性验证 {len(jobs)} 条知识，通过 {passed} 条，整体平均分 {avg_score}。",
            details={"run_id": context.run_id, "probe_ids": probe_ids[:20], "aggregate_feedback": aggregate},
        )
        context.outputs["comprehension_probe_ids"] = probe_ids
        return StepResult(
            metrics={
                "tested": len(jobs),
                "passed": passed,
                "failed": len(jobs) - passed,
                "avg_score": avg_score,
                "model_circuit_open": parallel.circuit_open,
                "model_max_concurrency": max_concurrency,
                "model_circuit_failure_threshold": circuit_failure_threshold,
            },
            artifacts=[artifact],
        )


def _upsert_probe(context: PipelineContext, knowledge_item: dict[str, Any], probe_payload: dict[str, Any]) -> int | None:
    """按 knowledge_id 幂等 upsert probe 条目。"""
    existing = context.conn.execute(
        "SELECT id FROM domain_items WHERE domain = ? AND item_type = ? AND json_extract(payload_json, '$.knowledge_id') = ? ORDER BY id DESC LIMIT 1",
        ("vulnerabilities", "comprehension_probe", knowledge_item["id"]),
    ).fetchone()
    title = f"可理解性验证：{probe_payload['knowledge_title'] or knowledge_item.get('title')}"
    summary = f"整体 {probe_payload['overall_score']} · {probe_payload['verdict']}"
    score = round(probe_payload["overall_score"] * 100, 2)
    status = "通过" if probe_payload["verdict"] == "pass" else "未通过"
    tags = ["可理解性验证", *[f"弱:{f}" for f in probe_payload["weak_fields"]], "双模型对拍" if probe_payload["model_used"] else "本地规则兜底"]
    metrics = {"pipeline_run": context.run_id, "knowledge_id": knowledge_item["id"], "overall_score": probe_payload["overall_score"], "verdict": probe_payload["verdict"]}
    if existing:
        repo.update_domain_item(
            context.conn,
            item_id=existing[0],
            title=title,
            summary=summary,
            status=status,
            score=score,
            tags=tags,
            payload=probe_payload,
            metrics=metrics,
        )
        return int(existing[0])
    return repo.create_domain_item(
        context.conn,
        domain="vulnerabilities",
        item_type="comprehension_probe",
        title=title,
        summary=summary,
        score=score,
        status=status,
        source="comprehension_prober",
        source_url="",
        primary_date="",
        tags=tags,
        metrics=metrics,
        payload=probe_payload,
    )


def _load_material_text(context: PipelineContext, knowledge_item: dict[str, Any]) -> str:
    """回溯素材正文：优先 material 的 cleaned_text/markdown/summary；素材缺失时用知识自身字段兜底。"""
    payload = knowledge_item.get("payload") or {}
    mat_id = payload.get("source_material_id")
    text = ""
    if mat_id:
        mrow = context.conn.execute(
            "SELECT * FROM domain_items WHERE domain = ? AND item_type = ? AND id = ?",
            ("vulnerabilities", "material", mat_id),
        ).fetchone()
        if mrow:
            mp = repo.row_to_dict(mrow).get("payload") or {}
            text = str(mp.get("cleaned_text") or mp.get("markdown") or mp.get("summary") or "").strip()
    if not text:
        parts: list[str] = []
        for key in ("summary", "root_cause_pattern", "trigger_condition", "mitigation_or_fix"):
            val = payload.get(key)
            if val:
                parts.append(str(val))
        for val in payload.get("key_findings") or []:
            parts.append(str(val))
        for val in payload.get("evidence_snippets") or []:
            if isinstance(val, dict):
                parts.append(str(val.get("snippet") or val.get("content") or val))
            else:
                parts.append(str(val))
        text = "\n".join(p for p in parts if p)
    return text


def _aggregate_summary(probe_payloads: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from ai4sec_platform.domains.vulnerabilities.comprehension_probers import aggregate_feedback

    return aggregate_feedback(probe_payloads)
