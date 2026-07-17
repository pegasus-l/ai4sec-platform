from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class BuildDomainItemStep:
    name: str = "build_domain_item"
    step_type: str = "build_domain_item"
    input_key: str = "deduped_items"
    output_key: str = "domain_item_ids"
    item_type: str = "item"
    builder: Callable[[dict[str, Any]], dict[str, Any]] | None = None

    def run(self, context: PipelineContext) -> StepResult:
        items = [item for item in list(context.outputs.get(self.input_key) or []) if isinstance(item, dict)]
        ids: list[int] = []
        for item in items:
            built = self.builder(item) if self.builder else item
            item_id = repo.create_domain_item(
                context.conn,
                domain=context.domain,
                item_type=built.get("item_type") or self.item_type,
                title=built.get("title") or item.get("title") or "未命名条目",
                summary=built.get("summary") or item.get("summary") or "",
                score=built.get("score") or item.get("score"),
                status=built.get("status") or item.get("status") or "active",
                source=built.get("source") or item.get("source") or "pipeline",
                source_url=built.get("source_url") or item.get("source_url") or item.get("url") or "",
                primary_date=built.get("primary_date") or item.get("primary_date") or "",
                tags=built.get("tags") or item.get("tags") or [],
                metrics=built.get("metrics") or {"pipeline_run": context.run_id},
                payload=built.get("payload") or item,
            )
            ids.append(item_id)
        context.outputs[self.output_key] = ids
        return StepResult(metrics={"built": len(ids), "output_key": self.output_key})
