from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.domains.threats.cve_authority import validate_high_fanout_cves
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class ValidateThreatCveAuthorityStep:
    name: str = "validate_threat_cve_authority"
    step_type: str = "quality_gate"

    def run(self, context: PipelineContext) -> StepResult:
        mode = str(context.params.get("cve_authority_mode") or "off").lower()
        if mode == "off":
            return StepResult(metrics={"mode": "off", "skipped": True})
        scout = context.outputs.get("huawei_cve_scout")
        if not isinstance(scout, dict):
            raise ValueError("huawei_cve_scout output is required for CVE authority validation")
        metrics = validate_high_fanout_cves(
            scout,
            cache_dir=context.settings.output_dir / "cache" / "threats" / "cve_authority",
            mode=mode,
            min_fanout=int(context.params.get("cve_authority_min_fanout", 5)),
            limit=int(context.params.get("cve_authority_limit", 25)),
            refresh=bool(context.params.get("cve_authority_refresh", False)),
        )
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="huawei_cve_authority",
            name="threats/huawei_cve_authority.json",
            data={"metrics": metrics, "items": _validation_items(scout)},
        )
        context.outputs["huawei_generated_cve_record"]["items"] = _items_from_scout(scout)
        return StepResult(metrics=metrics, artifacts=[artifact])


def _items_from_scout(data: dict) -> list[dict]:
    return [
        {"org": org, "name": name, **project}
        for org, org_data in (data.get("orgs") or {}).items()
        for name, project in (org_data.get("projects") or {}).items()
        if isinstance(project, dict)
    ]


def _validation_items(data: dict) -> list[dict]:
    return [
        {
            "org": org,
            "project": name,
            "cve_id": finding.get("cve_id") or "",
            "source_url": finding.get("source_url") or "",
            "risk_eligible": finding.get("risk_eligible", True),
            "authority_validation": finding["authority_validation"],
        }
        for org, org_data in (data.get("orgs") or {}).items()
        for name, project in (org_data.get("projects") or {}).items()
        for finding in project.get("cves") or []
        if isinstance(finding, dict) and finding.get("authority_validation")
    ]
