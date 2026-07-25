from __future__ import annotations

import sys
from dataclasses import dataclass

from ai4sec_platform.domains.threats.adapters.huawei_sources import (
    _collect_repo_records,
    _collect_live_assets,
    _requested_sources,
    load_huawei_sources,
)
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.sources.registry import SourceRegistry


@dataclass
class CollectHuaweiSourcesStep:
    name: str = "collect_huawei_sources"
    step_type: str = "collect_sources"

    def run(self, context: PipelineContext) -> StepResult:
        params = context.params

        # Always use live path with incremental DB writes — cache path had no incremental progress
        # and refresh_source_cache=true means cache is re-fetched anyway (cache files are pointless)
        registry = SourceRegistry()
        requested = _requested_sources(params)
        records: list[dict] = []
        artifacts = []

        # 1. Repos (the big one — 25 orgs × multiple pages)
        if "repos" in requested:
            print("[collect] Fetching repos from GitCode/AtomGit...", file=sys.stderr, flush=True)
            repo_records = _collect_repo_records(registry, params)
            for record in repo_records:
                records.append(record)
                # Write each source record as a raw_artifact immediately
                art = context.artifact_store.write_json(
                    context.conn, run_id=context.run_id,
                    artifact_type="huawei_source_records",
                    name=f"threats/{record.get('source', 'unknown')}.json",
                    data={"records": [record], "params": params},
                )
                artifacts.append(art)
                context.conn.commit()
                print(f"[collect] {record.get('source')}: {len(record.get('items') or [])} items written", file=sys.stderr, flush=True)

        # 2. Assets (firmware, ascendhub, mirrors, openx)
        asset_records = _collect_live_assets(registry, params, requested_sources=requested)
        if isinstance(asset_records, list):
            for record in asset_records:
                if isinstance(record, dict):
                    records.append(record)
                    art = context.artifact_store.write_json(
                        context.conn, run_id=context.run_id,
                        artifact_type="huawei_source_records",
                        name=f"threats/{record.get('source', 'unknown')}.json",
                        data={"records": [record], "params": params},
                    )
                    artifacts.append(art)
                    context.conn.commit()
                    print(f"[collect] {record.get('source')}: {len(record.get('items') or [])} items written", file=sys.stderr, flush=True)
        elif isinstance(asset_records, dict):
            records.append(asset_records)
            art = context.artifact_store.write_json(
                context.conn, run_id=context.run_id,
                artifact_type="huawei_source_records",
                name=f"threats/{asset_records.get('source', 'unknown')}.json",
                data={"records": [asset_records], "params": params},
            )
            artifacts.append(art)
            context.conn.commit()
            print(f"[collect] {asset_records.get('source')}: {len(asset_records.get('items') or [])} items written", file=sys.stderr, flush=True)

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

