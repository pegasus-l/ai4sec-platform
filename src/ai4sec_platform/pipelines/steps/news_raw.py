from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.news.adapters.ai_for_sec_raw import load_raw_sources
from ai4sec_platform.domains.news.builders import build_news_and_capability_items
from ai4sec_platform.domains.news.dedupe import dedupe_normalized_items
from ai4sec_platform.domains.news.normalizers import normalize_raw_item
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class ImportAiForSecRawStep:
    name: str = "import_ai_for_sec_raw"
    step_type: str = "raw_import"

    def run(self, context: PipelineContext) -> StepResult:
        date = str(context.params.get("date") or "2026-07-10")
        raw_dir = Path(context.settings.legacy_sources.get("ai_for_sec_raw_dir", ""))
        sources = load_raw_sources(raw_dir, date)
        artifacts = []
        raw_records = []
        for source in sources:
            artifact = context.artifact_store.write_json(
                context.conn,
                run_id=context.run_id,
                artifact_type=f"raw_{source['source']}",
                name=f"raw/{source['source']}.json",
                data={"source": source["source"], "path": source["path"], "exists": source["exists"], "items": source["items"]},
            )
            artifacts.append(artifact)
            raw_id = repo.create_raw_artifact(
                context.conn,
                run_id=context.run_id,
                domain="news",
                source=source["source"],
                source_type="ai_for_sec_raw",
                source_path=source["path"],
                item_count=len(source["items"]),
                payload={"exists": source["exists"], "artifact": artifact},
            )
            raw_records.append({"id": raw_id, **source})
        context.outputs["ai_for_sec_raw_sources"] = raw_records
        return StepResult(metrics={"date": date, "sources": len(sources), "items": sum(len(item["items"]) for item in sources)}, artifacts=artifacts)


@dataclass
class NormalizeAiForSecRawStep:
    name: str = "normalize_ai_for_sec_raw"
    step_type: str = "normalize"

    def run(self, context: PipelineContext) -> StepResult:
        raw_sources = context.outputs.get("ai_for_sec_raw_sources") or []
        normalized_count = 0
        for raw in raw_sources:
            for item in raw.get("items") or []:
                normalized = normalize_raw_item(raw["source"], item)
                repo.create_normalized_item(
                    context.conn,
                    run_id=context.run_id,
                    domain="news",
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
        items = repo.list_normalized_items(context.conn, run_id=context.run_id, domain="news", limit=10000)
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="normalized_news_items",
            name="normalized/news_items.json",
            data=items,
        )
        context.outputs["normalized_news_items"] = items
        return StepResult(metrics={"normalized_items": normalized_count}, artifacts=[artifact])


@dataclass
class BuildRawNewsDomainItemsStep:
    name: str = "build_raw_news_domain_items"
    step_type: str = "build_domain_item"

    def run(self, context: PipelineContext) -> StepResult:
        items = context.outputs.get("normalized_news_items") or repo.list_normalized_items(context.conn, run_id=context.run_id, domain="news", limit=10000)
        deduped = dedupe_normalized_items(items)
        counts = build_news_and_capability_items(context.conn, deduped, run_id=context.run_id)
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="deduped_news_items",
            name="deduped/news_items.json",
            data=deduped,
        )
        repo.create_quality_audit(
            context.conn,
            domain="news",
            audit_type="raw_pipeline_import",
            status="pass" if counts["news"] else "warn",
            score=1.0 if counts["news"] else 0.2,
            summary=f"Raw pipeline 构造资讯 {counts['news']} 条，能力候选 {counts['capabilities']} 条。",
            details={"run_id": context.run_id, "deduped": len(deduped)},
        )
        return StepResult(metrics={"deduped_items": len(deduped), **counts}, artifacts=[artifact])
