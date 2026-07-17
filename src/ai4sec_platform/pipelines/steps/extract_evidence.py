from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class ExtractEvidenceStep:
    name: str = "extract_evidence"
    step_type: str = "extract_evidence"
    item_ids_key: str = "domain_item_ids"
    items_key: str = "deduped_items"

    def run(self, context: PipelineContext) -> StepResult:
        ids = list(context.outputs.get(self.item_ids_key) or [])
        items = list(context.outputs.get(self.items_key) or [])
        created = 0
        for item_id, item in zip(ids, items):
            if not isinstance(item, dict):
                continue
            repo.create_evidence(context.conn, domain=context.domain, domain_item_id=int(item_id), evidence_type="pipeline_evidence", title=item.get("title") or "来源证据", content=item.get("summary") or item.get("content") or "", source_url=item.get("source_url") or item.get("url") or "", payload={"run_id": context.run_id})
            created += 1
        return StepResult(metrics={"evidence": created})
