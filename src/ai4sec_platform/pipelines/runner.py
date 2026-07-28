from __future__ import annotations

import time
from typing import Any

from ai4sec_platform.artifacts.manifest import write_manifest
from ai4sec_platform.artifacts.store import ArtifactStore
from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.core.ids import new_id
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db, reset_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.registry import PipelineRegistry, default_registry


class PipelineRunner:
    def __init__(self, settings: Settings | None = None, registry: PipelineRegistry | None = None) -> None:
        self.settings = settings or load_settings()
        self.registry = registry or default_registry()
        self.artifact_store = ArtifactStore(self.settings.output_dir)

    def run(self, pipeline_name: str, params: dict[str, Any] | None = None, *, run_id: str | None = None) -> dict[str, Any]:
        params = params or {}
        definition = self.registry.get(pipeline_name)
        run_id = run_id or new_id("run")
        started_at = utc_now()
        artifacts: list[dict[str, Any]] = []
        summary: dict[str, Any] = {
            "params": params,
            "steps": [],
            "current_step": "",
            "completed_steps": 0,
            "total_steps": len(definition.steps),
        }
        with connect(self.settings) as conn:
            if params.get("reset"):
                reset_db(conn)
            else:
                init_db(conn)
            repo.create_pipeline_run(
                conn,
                run_id=run_id,
                domain=definition.domain,
                pipeline_name=definition.name,
                status="running",
                started_at=started_at,
                finished_at="",
                production_writes=False,
                summary=summary,
            )
            conn.commit()  # Commit immediately so frontend can see running status
            context = PipelineContext(
                run_id=run_id,
                pipeline_name=definition.name,
                domain=definition.domain,
                settings=self.settings,
                conn=conn,
                artifact_store=self.artifact_store,
                params=params,
            )
            status = "success"
            error_message = ""
            for step in definition.steps:
                try:
                    summary["current_step"] = step.name
                    repo.create_pipeline_run(
                        conn,
                        run_id=run_id,
                        domain=definition.domain,
                        pipeline_name=definition.name,
                        status="running",
                        started_at=started_at,
                        finished_at="",
                        production_writes=False,
                        summary=summary,
                    )
                    conn.commit()
                    step_started = time.perf_counter()
                    result = step.run(context)
                    result.metrics["duration_ms"] = int((time.perf_counter() - step_started) * 1000)
                    context.outputs.setdefault("_step_metrics", {})[step.name] = dict(result.metrics)
                    artifacts.extend(result.artifacts)
                    summary["steps"].append({"name": step.name, "status": "success", "metrics": result.metrics})
                    summary["completed_steps"] = len(summary["steps"])
                    repo.create_task_run(conn, run_id=run_id, step_name=step.name, status="success", metrics=result.metrics)
                    repo.create_pipeline_run(
                        conn,
                        run_id=run_id,
                        domain=definition.domain,
                        pipeline_name=definition.name,
                        status="running",
                        started_at=started_at,
                        finished_at="",
                        production_writes=False,
                        summary=summary,
                    )
                    conn.commit()
                except Exception as exc:  # pragma: no cover - defensive run recording
                    status = "failed"
                    error_message = str(exc)
                    summary["steps"].append({"name": step.name, "status": "failed", "error": error_message})
                    summary["completed_steps"] = len(summary["steps"])
                    repo.create_task_run(conn, run_id=run_id, step_name=step.name, status="failed", error_message=error_message)
                    break
            summary["current_step"] = ""
            summary["status"] = status
            summary["error_message"] = error_message
            manifest = write_manifest(conn, self.artifact_store, run_id=run_id, summary=summary, artifacts=artifacts)
            repo.create_pipeline_run(
                conn,
                run_id=run_id,
                domain=definition.domain,
                pipeline_name=definition.name,
                status=status,
                started_at=started_at,
                finished_at=utc_now(),
                production_writes=False,
                summary={**summary, "manifest": manifest},
            )
            conn.commit()
        return {"run_id": run_id, "pipeline_name": definition.name, "domain": definition.domain, "status": status, "summary": summary}
