from __future__ import annotations

import sys
from dataclasses import dataclass

from ai4sec_platform.domains.threats.adapters.huawei_sources import load_huawei_sources
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class CollectHuaweiSourcesStep:
    name: str = "collect_huawei_sources"
    step_type: str = "collect_sources"

    def run(self, context: PipelineContext) -> StepResult:
        records = load_huawei_sources(context.settings, context.params)
        artifacts = self._write_records(context, records)
        context.outputs["huawei_source_records"] = records
        metrics = self._metrics(records)
        print(f"[collect] Done. {metrics['items']} total items from {metrics['sources']} sources", file=sys.stderr, flush=True)
        return StepResult(metrics=metrics, artifacts=artifacts)

    def _write_records(self, context: PipelineContext, records: list[dict]) -> list:
        artifacts = []
        artifact = context.artifact_store.write_json(
            context.conn, run_id=context.run_id,
            artifact_type="huawei_source_records",
            name="threats/huawei_source_records.json",
            data={"records": records, "params": context.params},
        )
        artifacts.append(artifact)
        org_security_materials = _items(records, "org_security_materials")
        if org_security_materials:
            org_artifact = context.artifact_store.write_json(
                context.conn, run_id=context.run_id,
                artifact_type="huawei_org_security_materials",
                name="threats/huawei_org_security_materials.json",
                data={"items": org_security_materials, "params": context.params},
            )
            artifacts.append(org_artifact)
        return artifacts

    def _metrics(self, records: list[dict]) -> dict:
        return {
            "sources": len(records),
            "items": sum(len(record.get("items") or []) for record in records),
            "items_by_source": {record.get("source", "unknown"): len(record.get("items") or []) for record in records},
        }


def _items(records: list[dict], source: str) -> list[dict]:
    for record in records:
        if record.get("source") == source:
            return record.get("items") or []
    return []
