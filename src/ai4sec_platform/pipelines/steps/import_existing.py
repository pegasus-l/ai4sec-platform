from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.importers.seed_demo_data import import_all_legacy_samples
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class ImportLegacySamplesStep:
    name: str = "import_legacy_samples"
    step_type: str = "import_existing"

    def run(self, context: PipelineContext) -> StepResult:
        results = import_all_legacy_samples(context.conn, context.settings)
        context.outputs["legacy_import_results"] = results
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="legacy_import_results",
            name="legacy_import_results.json",
            data=results,
        )
        return StepResult(metrics={"domains_imported": len(results), "reset": bool(context.params.get("reset"))}, artifacts=[artifact])
