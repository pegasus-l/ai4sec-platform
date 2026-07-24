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
        repos = _items(records, "repos")
        org_security_materials = _items(records, "org_security_materials")
        validation = validate_repo_projects(repos)
        cve_scout = build_cve_scout_from_local_records(repos, None, org_security_materials)
        cve_validation = validate_cve_scout_output(cve_scout)
        report = build_cve_scout_report(cve_scout)
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="huawei_cve_scout", name="threats/huawei_cve_scout.json", data=cve_scout)
        report_artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="huawei_cve_report", name="threats/huawei_cve_report.json", data=report)
        repo.create_quality_audit(context.conn, domain="threats", audit_type="huawei_repo_validation", status=validation["status"], score=1.0 if validation["status"] == "pass" else 0.6, summary=f"华为仓库字段校验：{validation['total']} 个项目，缺字段 {validation['missing_count']} 个。", details=validation)
        repo.create_quality_audit(context.conn, domain="threats", audit_type="huawei_cve_scout_validation", status=cve_validation["status"], score=1.0 if cve_validation["status"] == "pass" else 0.5, summary=report["summary"], details=cve_validation)
        coverage = _coverage_audit(cve_scout)
        repo.create_quality_audit(context.conn, domain="threats", audit_type="huawei_cve_coverage", status=coverage["status"], score=coverage["score"], summary=coverage["summary"], details=coverage)
        context.outputs["huawei_cve_scout"] = cve_scout
        context.outputs["huawei_generated_cve_record"] = {"source": "cve_findings", "path": "generated:huawei_cve_scout", "exists": True, "items": _items_from_generated_cve_scout(cve_scout), "raw": cve_scout, "mode": "generated"}
        return StepResult(metrics={"projects": len(repos), **cve_scout.get("meta", {})}, artifacts=[artifact, report_artifact])


def _items(records: list[dict], source: str) -> list[dict]:
    for record in records:
        if record.get("source") == source:
            return record.get("items") or []
    return []


def _items_from_generated_cve_scout(data: dict) -> list[dict]:
    items = []
    for org, org_data in (data.get("orgs") or {}).items():
        for name, project in (org_data.get("projects") or {}).items():
            if isinstance(project, dict):
                items.append({"org": org, "name": name, **project})
    return items


def _coverage_audit(data: dict) -> dict:
    meta = data.get("meta") or {}
    projects = int(meta.get("total_projects_in") or 0)
    total_sec = int(meta.get("total_sec_items") or 0)
    total_cve = int(meta.get("total_cve_ids") or 0)
    orgs_with_security_repo = meta.get("orgs_with_security_repo") or []
    coverage_ratio = (total_sec / projects) if projects else 0.0
    status = "pass"
    score = 0.9
    reasons = []
    if orgs_with_security_repo and total_cve == 0:
        status = "warn"
        score = 0.45
        reasons.append("发现 security repo 但未提取到明确 CVE，可能需要提高 security_file_limit/security_repo_limit 或检查目录递归。")
    if projects and coverage_ratio < 0.01:
        status = "warn"
        score = min(score, 0.5)
        reasons.append(f"安全线索覆盖率较低：{coverage_ratio:.2%}。")
    return {"status": status, "score": score, "summary": "；".join(reasons) if reasons else "CVE/SA 覆盖率通过基础检查。", "projects": projects, "total_sec_items": total_sec, "total_cve_ids": total_cve, "coverage_ratio": coverage_ratio, "orgs_with_security_repo": orgs_with_security_repo}
