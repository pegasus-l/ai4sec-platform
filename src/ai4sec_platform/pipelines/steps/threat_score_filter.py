from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.domains.threats.adapters.huawei_sources import load_huawei_sources
from ai4sec_platform.domains.threats.attack_surface_scoring import score_attack_surface
from ai4sec_platform.domains.threats.reports import build_attack_surface_report
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class HuaweiAttackSurfaceScoreStep:
    name: str = "huawei_attack_surface_score"
    step_type: str = "score_filter"

    def run(self, context: PipelineContext) -> StepResult:
        top_n = int(context.params.get("top_n", 50))
        records = context.outputs.get("huawei_source_records") or load_huawei_sources(context.settings, context.params)
        context.outputs["huawei_source_records"] = records
        mode = str(context.params.get("mode") or "local_raw")
        projects = _items(records, "scored_repos") or _items(records, "repos")
        scored = []
        for project in projects:
            result = score_attack_surface(project)
            output = {
                **project,
                "attack_surface_score": result.score,
                "grade": result.grade,
                "score_breakdown": result.breakdown,
                "primary_attack_surface": result.signals.get("primary_attack_surface", ""),
                "filtered": result.signals.get("filtered", False),
                "filtered_reason": result.signals.get("filtered_reason", ""),
                "deprioritized": result.signals.get("deprioritized", False),
            }
            scored.append(output)
        scored.sort(key=lambda item: (-float(item.get("attack_surface_score") or 0), -int(item.get("star_count") or 0), item.get("name", "")))
        ab = [item for item in scored if not item.get("filtered") and item.get("grade") in {"A", "B"}][:top_n]
        enriched = {item.get("name") for item in ab}
        for item in scored:
            if item.get("name") in enriched:
                item["_enrich_source"] = "ai4sec_attack_surface_score"
                item["_enrich_note"] = "Migrated from repo-info/huawei vuln_filter_pipeline.py semantics"
        report = build_attack_surface_report(scored)
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="huawei_attack_surface", name="threats/huawei_attack_surface.json", data={"projects": scored, "report": report})
        context.outputs["huawei_attack_surface_projects"] = scored
        return StepResult(metrics={"mode": mode, "projects": len(scored), "top_ab": len(ab), "total_kept": report["total_kept"], "total_dropped": report["total_dropped"]}, artifacts=[artifact])


def _items(records: list[dict], source: str) -> list[dict]:
    for record in records:
        if record.get("source") == source:
            return record.get("items") or []
    return []
