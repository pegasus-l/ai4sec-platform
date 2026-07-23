from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.news.adapters.sources import collect_news_sources
from ai4sec_platform.domains.news.builders import build_news_items
from ai4sec_platform.domains.news.dedupe import dedupe_normalized_items
from ai4sec_platform.domains.news.normalizers import normalize_raw_item
from ai4sec_platform.domains.news import repository as news_repo
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class CollectNewsSourcesStep:
    name: str = "collect_news_sources"
    step_type: str = "collect"

    def run(self, context: PipelineContext) -> StepResult:
        if "mode" not in context.params:
            context.params["mode"] = "legacy_raw" if context.pipeline_name == "news.legacy_raw_pipeline" else "shadow"
        records = collect_news_sources(context.settings, context.params)
        artifacts = []
        raw_records = []
        for record in records:
            artifact = context.artifact_store.write_json(
                context.conn,
                run_id=context.run_id,
                artifact_type=f"raw_news_{record['source']}",
                name=f"raw/news/{record['source']}.json",
                data={key: record.get(key) for key in ["source", "path", "exists", "mode", "items", "errors", "metadata"]},
            )
            artifacts.append(artifact)
            raw_id = repo.create_raw_artifact(
                context.conn,
                run_id=context.run_id,
                domain="news",
                source=record["source"],
                source_type=record.get("mode", "shadow"),
                source_path=record.get("path", ""),
                item_count=len(record.get("items") or []),
                payload={"exists": record.get("exists", True), "errors": record.get("errors", []), "artifact": artifact},
            )
            repo.create_data_source(
                context.conn,
                domain="news",
                name=record["source"],
                source_type=record.get("mode", "shadow"),
                status="ok" if not record.get("errors") else "degraded",
                health="ok" if not record.get("errors") else "degraded",
                summary={"items": len(record.get("items") or []), "errors": record.get("errors", []), "run_id": context.run_id},
            )
            raw_records.append({"id": raw_id, **record})
        context.outputs["news_raw_sources"] = raw_records
        return StepResult(metrics={"sources": len(records), "items": sum(len(record.get("items") or []) for record in records), "errors": sum(len(record.get("errors") or []) for record in records)}, artifacts=artifacts)


@dataclass
class NormalizeNewsStep:
    name: str = "normalize_news_items"
    step_type: str = "normalize"

    def run(self, context: PipelineContext) -> StepResult:
        records = context.outputs.get("news_raw_sources") or []
        normalized_count = 0
        for record in records:
            for raw_item in record.get("items") or []:
                normalized = normalize_raw_item(record["source"], raw_item)
                normalized["raw_artifact_ids"] = [record["id"]]
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
                    raw_artifact_id=record["id"],
                )
                normalized_count += 1
        items = repo.list_normalized_items(context.conn, run_id=context.run_id, domain="news", limit=100000)
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="normalized_news_items", name="normalized/news_items.json", data=items)
        context.outputs["normalized_news_items"] = items
        return StepResult(metrics={"normalized_items": normalized_count}, artifacts=[artifact])


@dataclass
class BuildNewsItemsStep:
    name: str = "build_news_items"
    step_type: str = "build_domain_item"

    def run(self, context: PipelineContext) -> StepResult:
        raw_items = context.outputs.get("normalized_news_items") or []
        deduped = dedupe_normalized_items(raw_items)
        counts = build_news_items(context.conn, deduped, run_id=context.run_id)
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="deduped_news_items", name="deduped/news_items.json", data=deduped)
        context.outputs["news_item_ids"] = counts.get("item_ids", [])
        context.outputs["news_items"] = deduped
        return StepResult(metrics={"deduped_items": len(deduped), **{key: value for key, value in counts.items() if key != "item_ids"}}, artifacts=[artifact])


@dataclass
class BuildNewsDailyReportStep:
    name: str = "build_news_daily_report"
    step_type: str = "build_report"

    def run(self, context: PipelineContext) -> StepResult:
        report_date = str(context.params.get("date") or datetime.now(timezone.utc).date().isoformat())
        item_ids = context.outputs.get("news_item_ids") or []
        selected = []
        for item_id in item_ids:
            item = repo.get_domain_item(context.conn, "news", int(item_id))
            if item and (float(item.get("score") or 0) >= 55):
                selected.append(item)
        selected.sort(key=lambda item: (float(item.get("score") or 0), item.get("primary_date", "")), reverse=True)
        highlights = [int(item["id"]) for item in selected[:12]]
        topic_items: dict[str, list[int]] = {}
        for item in selected:
            payload = item.get("payload") or {}
            topics = payload.get("topics") or payload.get("classification", {}).get("tags") or ["其他"]
            for topic in topics[:3]:
                topic_items.setdefault(str(topic), []).append(int(item["id"]))
        topic_sections = [{"topic": topic, "item_ids": ids[:10], "summary": f"{topic} 相关资讯 {len(ids)} 条。"} for topic, ids in sorted(topic_items.items(), key=lambda pair: len(pair[1]), reverse=True)[:10]]
        summary = f"本次采集发现 {len(item_ids)} 条资讯，其中 {len(highlights)} 条进入精选。"
        metrics = {"item_count": len(item_ids), "highlight_count": len(highlights), "topic_count": len(topic_sections)}
        news_repo.upsert_daily_report(conn=context.conn, report_date=report_date, title=f"AI4SEC 资讯日报 · {report_date}", summary=summary, highlights=highlights, topic_sections=topic_sections, metrics=metrics, run_id=context.run_id)
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="news_daily_report", name=f"reports/news_{report_date}.json", data={"report_date": report_date, "summary": summary, "highlights": highlights, "topic_sections": topic_sections, "metrics": metrics})
        context.outputs["news_daily_report"] = {"report_date": report_date, "highlights": highlights, "topic_sections": topic_sections}
        return StepResult(metrics=metrics, artifacts=[artifact])


@dataclass
class AuditNewsStep:
    name: str = "audit_news_quality"
    step_type: str = "audit"

    def run(self, context: PipelineContext) -> StepResult:
        items = context.outputs.get("news_items") or []
        missing_title = sum(1 for item in items if not item.get("title"))
        missing_url = sum(1 for item in items if not item.get("url"))
        score = max(0.0, 1.0 - (missing_title + missing_url) / max(1, len(items) * 2))
        status = "pass" if score >= 0.9 else "warn" if score >= 0.6 else "fail"
        repo.create_quality_audit(context.conn, domain="news", audit_type="news_quality", status=status, score=score, summary=f"资讯质量审计：{len(items)} 条，缺标题 {missing_title} 条，缺链接 {missing_url} 条。", details={"run_id": context.run_id, "missing_title": missing_title, "missing_url": missing_url})
        return StepResult(metrics={"items": len(items), "missing_title": missing_title, "missing_url": missing_url, "score": score})
