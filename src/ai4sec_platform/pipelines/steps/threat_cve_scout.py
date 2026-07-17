from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.threats.adapters.huawei_sources import load_huawei_sources
from ai4sec_platform.domains.threats.cve_scout import build_cve_scout_from_local_records
from ai4sec_platform.domains.threats.reports import build_cve_scout_report
from ai4sec_platform.domains.threats.validators import validate_cve_scout_output, validate_repo_projects
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class HuaweiCveScoutStep:
    name: str = "huawei_cve_scout"
    step_type: str = "cve_scout"

    def run(self, context: PipelineContext) -> StepResult:
        records = context.outputs.get("huawei_source_records") or load_huawei_sources(context.settings, context.params)
        context.outputs["huawei_source_records"] = records
        mode = str(context.params.get("mode") or "local_raw")
        repos = _items(records, "repos") or _items(records, "scored_repos")
        existing_cve = _raw(records, "repo_cves") or {}
        validation = validate_repo_projects(repos)
        cve_scout = build_cve_scout_from_local_records(repos, existing_cve.get("orgs") if isinstance(existing_cve, dict) else {})
        cve_validation = validate_cve_scout_output(cve_scout)
        report = build_cve_scout_report(cve_scout)
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="huawei_cve_scout", name="threats/huawei_cve_scout.json", data=cve_scout)
        report_artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="huawei_cve_report", name="threats/huawei_cve_report.json", data=report)
        repo.create_quality_audit(context.conn, domain="threats", audit_type="huawei_repo_validation", status=validation["status"], score=1.0 if validation["status"] == "pass" else 0.6, summary=f"华为仓库字段校验：{validation['total']} 个项目，缺字段 {validation['missing_count']} 个。", details=validation)
        repo.create_quality_audit(context.conn, domain="threats", audit_type="huawei_cve_scout_validation", status=cve_validation["status"], score=1.0 if cve_validation["status"] == "pass" else 0.5, summary=report["summary"], details=cve_validation)
        context.outputs["huawei_cve_scout"] = cve_scout
        return StepResult(metrics={"mode": mode, "projects": len(repos), **cve_scout.get("meta", {})}, artifacts=[artifact, report_artifact])


def _items(records: list[dict], source: str) -> list[dict]:
    for record in records:
        if record.get("source") == source:
            return record.get("items") or []
    return []


def _raw(records: list[dict], source: str):
    for record in records:
        if record.get("source") == source:
            return record.get("raw")
    return None
