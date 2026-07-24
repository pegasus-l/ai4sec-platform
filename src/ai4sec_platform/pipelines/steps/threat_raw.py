from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.threats.adapters.huawei_sources import load_huawei_sources
from ai4sec_platform.domains.threats.builders import build_threat_items
from ai4sec_platform.domains.threats.normalizers import normalize_huawei_item
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult

TARGET_SOURCES = {"repos", "cve_findings"}


@dataclass
class ImportHuaweiRawStep:
    name: str = "import_huawei_raw"
    step_type: str = "raw_import"

    def run(self, context: PipelineContext) -> StepResult:
        sources = context.outputs.get("huawei_source_records") or load_huawei_sources(context.settings, context.params)
        generated_cve_record = context.outputs.get("huawei_generated_cve_record")
        if generated_cve_record:
            sources = [record for record in sources if record.get("source") != "cve_findings"] + [generated_cve_record]
        context.outputs["huawei_source_records"] = sources
        artifacts = []
        raw_records = []
        for source in sources:
            artifact = context.artifact_store.write_json(
                context.conn,
                run_id=context.run_id,
                artifact_type=f"raw_huawei_{source['source']}",
                name=f"raw/huawei/{source['source']}.json",
                data={"source": source["source"], "path": source["path"], "exists": source["exists"], "items": source["items"][:500]},
            )
            artifacts.append(artifact)
            raw_id = repo.create_raw_artifact(
                context.conn,
                run_id=context.run_id,
                domain="threats",
                source=source["source"],
                source_type="huawei_raw",
                source_path=source["path"],
                item_count=len(source["items"]),
                payload={"exists": source["exists"], "artifact": artifact, "mode": source.get("mode") or "connector"},
            )
            raw_records.append({"id": raw_id, **source})
        context.outputs["huawei_raw_sources"] = raw_records
        return StepResult(metrics={"sources": len(sources), "items": sum(len(item["items"]) for item in sources)}, artifacts=artifacts)


@dataclass
class NormalizeHuaweiRawStep:
    name: str = "normalize_huawei_raw"
    step_type: str = "normalize"

    def run(self, context: PipelineContext) -> StepResult:
        raw_sources = context.outputs.get("huawei_raw_sources") or []
        limit = int(context.params.get("limit", 9999))
        normalized_count = 0
        for raw in raw_sources:
            if raw.get("source") not in TARGET_SOURCES:
                continue
            for item in (raw.get("items") or [])[:limit]:
                normalized = normalize_huawei_item(raw["source"], item)
                repo.create_normalized_item(
                    context.conn,
                    run_id=context.run_id,
                    domain="threats",
                    item_key=normalized["item_key"],
                    source=normalized["source"],
                    source_type=normalized["source_type"],
                    title=normalized["title"],
                    url=normalized.get("url", ""),
                    primary_date=normalized.get("primary_date", ""),
                    normalized=normalized,
                    raw_artifact_id=raw["id"],
                )
                normalized_count += 1
        items = repo.list_normalized_items(context.conn, run_id=context.run_id, domain="threats", limit=10000)
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="normalized_threat_items", name="normalized/threat_items.json", data=items)
        context.outputs["normalized_threat_items"] = items
        return StepResult(metrics={"normalized_items": normalized_count, "per_source_limit": limit, "sources": sorted(TARGET_SOURCES)}, artifacts=[artifact])


@dataclass
class BuildHuaweiThreatItemsStep:
    name: str = "build_huawei_threat_items"
    step_type: str = "build_domain_item"

    def run(self, context: PipelineContext) -> StepResult:
        items = context.outputs.get("normalized_threat_items") or repo.list_normalized_items(context.conn, run_id=context.run_id, domain="threats", limit=10000)
        counts = build_threat_items(
            context.conn,
            items,
            run_id=context.run_id,
            enrich_repo_summaries=bool(context.params.get("enrich_repo_summaries", True)),
            repo_summary_limit=int(context.params.get("repo_summary_limit", 50)),
            repo_summary_cache_dir=context.settings.output_dir / "cache" / "threats" / "repo_summaries",
        )
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="built_threat_items", name="built/threat_items.json", data={"counts": counts})
        repo.create_quality_audit(context.conn, domain="threats", audit_type="huawei_raw_pipeline", status="pass" if counts["items"] else "warn", score=1.0 if counts["items"] else 0.2, summary=f"Huawei raw pipeline 构造威胁对象 {counts['items']} 个。", details={"run_id": context.run_id})
        return StepResult(metrics=counts, artifacts=[artifact])
