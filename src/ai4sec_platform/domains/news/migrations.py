from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.pipelines.steps.news import AuditNewsStep, BuildNewsDailyReportStep, BuildNewsItemsStep, DeduplicateNewsStep, EnrichNewsCandidatesStep, ExtractNewsReferencesStep, GateNewsCandidatesStep, NormalizeNewsStep, ResolveNewsLinksStep, persist_news_source_records


MIGRATION_PIPELINE_NAME = "migration.news_legacy_raw_import"
SOURCE_FILES = {
    "arxiv": "arxiv_{date_compact}.json",
    "github": "github_{date_compact}.json",
    "rss": "rss_new_candidates_{date_compact}.json",
    "x": "x_new_candidates_{date_compact}.json",
    "asis": "asis_new_candidates_{date_compact}.json",
    "awesome": "awesome_candidates_{date_compact}.json",
}


@dataclass
class ImportLegacyNewsSourcesStep:
    source_dir: Path
    import_date: str
    name: str = "collect_news_sources"
    step_type: str = "migration"

    def run(self, context: PipelineContext) -> StepResult:
        records = [
            {
                **record,
                "mode": "legacy_migration",
                "errors": [] if record["exists"] else ["source_file_missing"],
            }
            for record in load_legacy_news_sources(self.source_dir, self.import_date)
        ]
        return persist_news_source_records(context, records)


def legacy_news_import_pipeline(source_dir: Path, import_date: str) -> PipelineDefinition:
    return PipelineDefinition(
        name=MIGRATION_PIPELINE_NAME,
        domain="news",
        steps=[
            ImportLegacyNewsSourcesStep(source_dir=source_dir, import_date=import_date),
            ExtractNewsReferencesStep(),
            NormalizeNewsStep(),
            DeduplicateNewsStep(),
            ResolveNewsLinksStep(),
            GateNewsCandidatesStep(),
            EnrichNewsCandidatesStep(),
            BuildNewsItemsStep(),
            BuildNewsDailyReportStep(),
            AuditNewsStep(),
        ],
    )


def load_legacy_news_sources(source_dir: Path, import_date: str) -> list[dict[str, Any]]:
    date_compact = import_date.replace("-", "")
    records: list[dict[str, Any]] = []
    for source, pattern in SOURCE_FILES.items():
        path = source_dir / pattern.format(date_compact=date_compact)
        if not path.exists():
            records.append({"source": source, "path": str(path), "exists": False, "items": []})
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        records.append({"source": source, "path": str(path), "exists": True, "items": extract_legacy_items(source, data)})
    return records


def extract_legacy_items(source: str, data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if not isinstance(data, dict):
        return []
    for key in ["items", "entries", "candidates", "papers", "repos", "results", "new_candidates"]:
        value = data.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    if source == "github" and isinstance(data.get("repositories"), list):
        return [item for item in data["repositories"] if isinstance(item, dict)]
    if source in {"rss", "x", "asis", "awesome"}:
        references: list[dict[str, Any]] = []
        for key in ["new_papers", "new_repos", "paper_refs", "repo_refs", "high_value_items"]:
            value = data.get(key)
            if isinstance(value, list):
                references.extend(item for item in value if isinstance(item, dict))
        if references:
            return references
    return []
