from __future__ import annotations

import hashlib
import inspect
import json
import sqlite3
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ai4sec_platform.artifacts.checksum import sha256_file
from ai4sec_platform.artifacts.manifest import write_manifest
from ai4sec_platform.artifacts.store import ArtifactStore
from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.core.ids import new_id
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db, reset_domain
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.registry import PipelineRegistry, default_registry


class PipelineRunner:
    def __init__(self, settings: Settings | None = None, registry: PipelineRegistry | None = None) -> None:
        self.settings = settings or load_settings()
        self.registry = registry or default_registry()
        self.artifact_store = ArtifactStore(self.settings.output_dir)

    def run(
        self,
        pipeline_name: str,
        params: dict[str, Any] | None = None,
        *,
        run_id: str | None = None,
        should_cancel: Callable[[], bool] | None = None,
    ) -> dict[str, Any]:
        params = params or {}
        definition = self.registry.get(pipeline_name)
        run_id = run_id or new_id("run")
        resume_from_run_id = str(params.get("_resume_from_run_id") or "")
        if resume_from_run_id and params.get("reset"):
            raise ValueError("A resumed pipeline run cannot also reset its domain")
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
                init_db(conn)
                reset_domain(conn, definition.domain, preserve_run_id=run_id)
            else:
                init_db(conn)
            context = PipelineContext(
                run_id=run_id,
                pipeline_name=definition.name,
                domain=definition.domain,
                settings=self.settings,
                conn=conn,
                artifact_store=self.artifact_store,
                params=params,
                should_cancel=should_cancel or (lambda: False),
            )
            resumed_steps = self._restore_checkpoint(conn, context, definition, resume_from_run_id) if resume_from_run_id else []
            if resumed_steps:
                summary["steps"] = resumed_steps
                summary["completed_steps"] = len(resumed_steps)
                summary["resumed_from_run_id"] = resume_from_run_id
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
            if resumed_steps:
                for step in resumed_steps:
                    repo.create_task_run(conn, run_id=run_id, step_name=step["name"], status="restored", metrics=step.get("metrics") or {})
                conn.commit()
            status = "success"
            error_message = ""
            for step in definition.steps[len(resumed_steps) :]:
                if should_cancel and should_cancel():
                    status = "cancelled"
                    error_message = "cancelled at step boundary"
                    break
                transaction_mode = "atomic"
                artifact_baseline_id = 0
                step_savepoint_started = False
                step_committed = False
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
                    transaction_mode = _step_transaction_mode(step)
                    artifact_baseline_id = _latest_artifact_id(conn, run_id)
                    if transaction_mode == "atomic":
                        conn.execute("SAVEPOINT pipeline_step")
                        step_savepoint_started = True
                        context.conn = _AtomicStepConnection(conn)  # type: ignore[assignment]
                    step_started = time.perf_counter()
                    try:
                        result = step.run(context)
                    finally:
                        context.conn = conn
                    step_status = str(result.status or "success")
                    if step_status not in {"success", "partial"}:
                        raise ValueError(f"Invalid StepResult status for {step.name}: {step_status}")
                    if step_savepoint_started:
                        conn.execute("RELEASE pipeline_step")
                        step_savepoint_started = False
                    result.metrics["duration_ms"] = int((time.perf_counter() - step_started) * 1000)
                    context.outputs.setdefault("_step_metrics", {})[step.name] = dict(result.metrics)
                    artifacts.extend(result.artifacts)
                    summary["steps"].append({
                        "name": step.name,
                        "status": step_status,
                        "transaction_mode": transaction_mode,
                        "message": result.message,
                        "metrics": result.metrics,
                    })
                    if step_status == "partial":
                        status = "partial"
                    summary["completed_steps"] = len(summary["steps"])
                    repo.create_task_run(conn, run_id=run_id, step_name=step.name, status=step_status, metrics=result.metrics, error_message=result.message)
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
                    step_committed = True
                    checkpoint = self._write_checkpoint(conn, context, definition, summary)
                    if checkpoint:
                        artifacts.append(checkpoint)
                        conn.commit()
                    if should_cancel and should_cancel():
                        status = "cancelled"
                        error_message = "cancelled at step boundary"
                        break
                except Exception as exc:  # pragma: no cover - defensive run recording
                    context.conn = conn
                    if not step_committed and transaction_mode == "atomic":
                        failed_artifacts = _artifact_paths_after(conn, run_id, artifact_baseline_id)
                        if step_savepoint_started:
                            _rollback_step_savepoint(conn)
                        else:
                            conn.rollback()
                        _remove_failed_artifacts(failed_artifacts, self.settings.output_dir)
                    else:
                        conn.rollback()
                    status = "timeout" if isinstance(exc, TimeoutError) else "failed"
                    error_message = str(exc)
                    summary["steps"].append({
                        "name": step.name,
                        "status": status,
                        "transaction_mode": transaction_mode,
                        "error": error_message,
                    })
                    summary["completed_steps"] = len(summary["steps"])
                    repo.create_task_run(conn, run_id=run_id, step_name=step.name, status=status, error_message=error_message)
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

    def _write_checkpoint(
        self,
        conn,
        context: PipelineContext,
        definition,
        summary: dict[str, Any],
    ) -> dict[str, Any] | None:
        next_step_contract = _next_step_resume_contract(definition.steps, len(summary["steps"]))
        if not next_step_contract or not next_step_contract["resume_safe"] or next_step_contract["resume_input_keys"] is None:
            return None
        input_keys = list(next_step_contract["resume_input_keys"])
        if any(key not in context.outputs for key in input_keys):
            return None
        payload = {
            "version": 1,
            "pipeline_name": definition.name,
            "domain": definition.domain,
            "input_checksum": _input_checksum(definition.name, definition.domain, definition.steps, context.params),
            "completed_steps": summary["steps"],
            "outputs": {key: context.outputs[key] for key in input_keys},
            "next_step": next_step_contract,
        }
        try:
            json.dumps(payload, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            return None
        step_index = len(summary["steps"])
        step_name = str(summary["steps"][-1]["name"])
        return context.artifact_store.write_json(
            conn,
            run_id=context.run_id,
            artifact_type="pipeline_checkpoint",
            name=f"checkpoints/{step_index:03d}_{step_name}.json",
            data=payload,
        )

    def _restore_checkpoint(self, conn, context: PipelineContext, definition, resume_from_run_id: str) -> list[dict[str, Any]]:
        source_run = conn.execute("SELECT status FROM pipeline_runs WHERE run_id = ?", (resume_from_run_id,)).fetchone()
        if not source_run or source_run["status"] not in {"failed", "cancelled"}:
            raise ValueError("Only failed or cancelled pipeline runs can be resumed")
        row = conn.execute(
            """
            SELECT path, sha256 FROM artifacts
            WHERE run_id = ? AND artifact_type = 'pipeline_checkpoint'
            ORDER BY id DESC LIMIT 1
            """,
            (resume_from_run_id,),
        ).fetchone()
        if not row:
            raise ValueError(f"No recoverable checkpoint found for run: {resume_from_run_id}")
        path = Path(str(row["path"])).resolve()
        expected_directory = context.artifact_store.run_dir(resume_from_run_id).resolve()
        if not path.is_relative_to(expected_directory):
            raise ValueError(f"Checkpoint artifact path is outside its run directory: {resume_from_run_id}")
        if not path.is_file() or sha256_file(path) != str(row["sha256"]):
            raise ValueError(f"Checkpoint artifact verification failed for run: {resume_from_run_id}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        expected_checksum = _input_checksum(definition.name, definition.domain, definition.steps, context.params)
        if (
            payload.get("version") != 1
            or payload.get("pipeline_name") != definition.name
            or payload.get("domain") != definition.domain
            or payload.get("input_checksum") != expected_checksum
        ):
            raise ValueError("Checkpoint does not match the current pipeline definition or input parameters")
        completed_steps = list(payload.get("completed_steps") or [])
        if len(completed_steps) >= len(definition.steps):
            raise ValueError("Checkpoint already contains every pipeline step")
        expected_names = [step.name for step in definition.steps[: len(completed_steps)]]
        if [step.get("name") for step in completed_steps] != expected_names:
            raise ValueError("Checkpoint step sequence does not match the current pipeline")
        next_step = definition.steps[len(completed_steps)]
        if not bool(getattr(next_step, "resume_safe", False)):
            raise ValueError(f"Pipeline step is not approved for automatic resume: {next_step.name}")
        expected_contract = _next_step_resume_contract(definition.steps, len(completed_steps))
        if payload.get("next_step") != expected_contract:
            raise ValueError("Checkpoint resume input contract does not match the current pipeline")
        outputs = payload.get("outputs")
        if not isinstance(outputs, dict):
            raise ValueError("Checkpoint outputs are invalid")
        context.outputs.update(outputs)
        return [{**step, "status": "restored"} for step in completed_steps]


def _step_transaction_mode(step: Any) -> str:
    mode = str(getattr(step, "transaction_mode", "atomic"))
    if mode not in {"atomic", "checkpointed"}:
        raise ValueError(f"Invalid transaction_mode for step {step.name}: {mode}")
    return mode


def _latest_artifact_id(conn: sqlite3.Connection, run_id: str) -> int:
    row = conn.execute("SELECT COALESCE(MAX(id), 0) FROM artifacts WHERE run_id = ?", (run_id,)).fetchone()
    return int(row[0])


def _artifact_paths_after(conn: sqlite3.Connection, run_id: str, artifact_id: int) -> list[str]:
    rows = conn.execute(
        "SELECT path FROM artifacts WHERE run_id = ? AND id > ?",
        (run_id, artifact_id),
    ).fetchall()
    return [str(row[0]) for row in rows]


def _rollback_step_savepoint(conn: sqlite3.Connection) -> None:
    try:
        conn.execute("ROLLBACK TO pipeline_step")
        conn.execute("RELEASE pipeline_step")
    except sqlite3.Error:
        conn.rollback()


def _remove_failed_artifacts(paths: list[str], output_dir: Path) -> None:
    root = output_dir.resolve()
    for raw_path in paths:
        path = Path(raw_path).resolve()
        if path.is_relative_to(root) and path.is_file():
            path.unlink(missing_ok=True)


class _AtomicStepConnection:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def commit(self) -> None:
        raise RuntimeError("Atomic pipeline steps must not commit; declare transaction_mode='checkpointed'")

    def rollback(self) -> None:
        raise RuntimeError("Atomic pipeline steps must not rollback the Runner-owned transaction")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._conn, name)


def _input_checksum(pipeline_name: str, domain: str, steps: list[Any], params: dict[str, Any]) -> str:
    semantic_params = {key: value for key, value in params.items() if key not in {"reset", "_resume_from_run_id"}}
    payload = {
        "pipeline_name": pipeline_name,
        "domain": domain,
        "steps": [_step_identity(step) for step in steps],
        "params": semantic_params,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _step_identity(step: Any) -> dict[str, Any]:
    step_class = step.__class__
    try:
        source = inspect.getsource(step_class)
    except (OSError, TypeError):
        source = f"{step_class.__module__}.{step_class.__qualname__}"
    return {
        "name": step.name,
        "step_type": step.step_type,
        "transaction_mode": _step_transaction_mode(step),
        "class": f"{step_class.__module__}.{step_class.__qualname__}",
        "checkpoint_version": getattr(step, "checkpoint_version", 1),
        "resume_safe": bool(getattr(step, "resume_safe", False)),
        "resume_input_keys": list(getattr(step, "resume_input_keys", []) or []),
        "implementation_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }


def _next_step_resume_contract(steps: list[Any], completed_count: int) -> dict[str, Any] | None:
    if completed_count >= len(steps):
        return None
    step = steps[completed_count]
    resume_input_keys = getattr(step, "resume_input_keys", None)
    return {
        "name": step.name,
        "resume_safe": bool(getattr(step, "resume_safe", False)),
        "resume_input_keys": list(resume_input_keys) if resume_input_keys is not None else None,
    }
