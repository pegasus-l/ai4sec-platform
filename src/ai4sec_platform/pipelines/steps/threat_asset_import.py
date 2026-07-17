from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.threats.adapters.huawei_sources import load_huawei_sources
from ai4sec_platform.domains.threats.builders import build_threat_items
from ai4sec_platform.domains.threats.normalizers import normalize_huawei_item
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult

ASSET_SOURCES = {"firmware", "ascendhub", "mirrors"}


@dataclass
class ImportHuaweiThreatAssetsStep:
    name: str = "import_huawei_threat_assets"
    step_type: str = "asset_import"

    def run(self, context: PipelineContext) -> StepResult:
        all_records = context.outputs.get("huawei_source_records") or load_huawei_sources(context.settings, context.params)
        context.outputs["huawei_source_records"] = all_records
        mode = str(context.params.get("mode") or "local_raw")
        records = [record for record in all_records if record.get("source") in ASSET_SOURCES]
        normalized_records = []
        artifacts = []
        for record in records:
            artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type=f"raw_{record['source']}", name=f"raw/threat_assets/{record['source']}.json", data={"source": record["source"], "path": record["path"], "items": record["items"], "exists": record["exists"]})
            artifacts.append(artifact)
            raw_id = repo.create_raw_artifact(context.conn, run_id=context.run_id, domain="threats", source=record["source"], source_type="huawei_asset_raw", source_path=record["path"], item_count=len(record["items"]), payload={"exists": record["exists"], "artifact": artifact})
            for item in record.get("items") or []:
                normalized = normalize_huawei_item(record["source"], item)
                repo.create_normalized_item(context.conn, run_id=context.run_id, domain="threats", item_key=normalized["item_key"], source=normalized["source"], source_type=normalized["source_type"], title=normalized["title"], url=normalized.get("url", ""), primary_date=normalized.get("primary_date", ""), normalized=normalized, raw_artifact_id=raw_id)
                normalized_records.append({"normalized_json": repo.dumps(normalized), **normalized})
        counts = build_threat_items(context.conn, normalized_records, run_id=context.run_id)
        repo.create_quality_audit(context.conn, domain="threats", audit_type="huawei_asset_import", status="pass" if counts["items"] else "warn", score=1.0 if counts["items"] else 0.2, summary=f"华为固件/镜像/资产导入 {counts['items']} 个对象。", details={"run_id": context.run_id, "sources": [r["source"] for r in records]})
        return StepResult(metrics={"mode": mode, "sources": len(records), "normalized": len(normalized_records), **counts}, artifacts=artifacts)
