from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.threats.reports import build_attack_surface_report, build_cve_scout_report
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class BuildHuaweiThreatReportStep:
    name: str = "build_huawei_threat_report"
    step_type: str = "report"

    def run(self, context: PipelineContext) -> StepResult:
        targets = repo.list_domain_items(context.conn, "threats", item_type="target", limit=500)
        assets = repo.list_domain_items(context.conn, "threats", item_type="asset", limit=500)
        cve_scout = context.outputs.get("huawei_cve_scout") or {}
        attack_projects = context.outputs.get("huawei_attack_surface_projects") or []
        report = {
            "title": "华为威胁洞察迁移报告",
            "targets": len(targets),
            "assets": len(assets),
            "high_risk_targets": [item for item in targets if float(item.get("score") or 0) >= 75][:50],
            "cve_scout_report": build_cve_scout_report(cve_scout) if cve_scout else {},
            "attack_surface_report": build_attack_surface_report(attack_projects) if attack_projects else {},
        }
        artifact = context.artifact_store.write_json(context.conn, run_id=context.run_id, artifact_type="huawei_threat_report", name="threats/huawei_threat_report.json", data=report)
        repo.create_quality_audit(context.conn, domain="threats", audit_type="huawei_threat_report", status="pass", score=0.9, summary=f"生成华为威胁报告：targets={len(targets)}, assets={len(assets)}。", details={"run_id": context.run_id})
        return StepResult(metrics={"targets": len(targets), "assets": len(assets), "high_risk": len(report["high_risk_targets"])}, artifacts=[artifact])
