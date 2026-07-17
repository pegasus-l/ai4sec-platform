from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class AuditStep:
    name: str = "audit"
    step_type: str = "audit"
    input_key: str = "domain_item_ids"
    audit_type: str = "pipeline_audit"

    def run(self, context: PipelineContext) -> StepResult:
        items = list(context.outputs.get(self.input_key) or [])
        status = "pass" if items else "warn"
        score = 0.9 if items else 0.2
        repo.create_quality_audit(context.conn, domain=context.domain, audit_type=self.audit_type, status=status, score=score, summary=f"{context.pipeline_name} 产出 {len(items)} 条。", details={"run_id": context.run_id, "input_key": self.input_key})
        return StepResult(metrics={"audited": len(items), "status": status})
