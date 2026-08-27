from __future__ import annotations

import concurrent.futures
import threading
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
from ai4sec_platform.pipelines.results import StepResult

# 默认单 step 超时 / 单 run 最大时长, 均可用 run params 覆盖。
DEFAULT_STEP_TIMEOUT_SECONDS = 21600.0   # 6h
DEFAULT_MAX_RUN_DURATION_SECONDS = 72000.0  # 20h


class _StepTimeout(Exception):
    """step 运行超过 step_timeout_seconds。"""


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
            "last_progress_at": started_at,
        }
        try:
            step_timeout = float(params.get("step_timeout_seconds", DEFAULT_STEP_TIMEOUT_SECONDS))
        except (TypeError, ValueError):
            step_timeout = DEFAULT_STEP_TIMEOUT_SECONDS
        try:
            max_run_duration = float(params.get("max_run_duration_seconds", DEFAULT_MAX_RUN_DURATION_SECONDS))
        except (TypeError, ValueError):
            max_run_duration = DEFAULT_MAX_RUN_DURATION_SECONDS
        run_started_monotonic = time.monotonic()
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
                if time.monotonic() - run_started_monotonic >= max_run_duration:
                    status, error_message = "interrupted", f"run exceeded max_run_duration_seconds={max_run_duration:g}"
                    summary["steps"].append({"name": step.name, "status": "interrupted", "error": error_message})
                    summary["completed_steps"] = len(summary["steps"])
                    repo.create_task_run(conn, run_id=run_id, step_name=step.name, status="interrupted", error_message=error_message)
                    break
                if not _is_run_running(conn, run_id):
                    status, error_message = "interrupted", "superseded by reaper (status not running)"
                    summary["steps"].append({"name": step.name, "status": "interrupted", "error": error_message})
                    summary["completed_steps"] = len(summary["steps"])
                    break
                try:
                    summary["current_step"] = step.name
                    summary["last_progress_at"] = utc_now()
                    if _is_run_running(conn, run_id):  # 状态权威: 被看门狗打断的 run 不复活
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
                    result = _run_step_with_timeout(step, context, step_timeout)
                    result.metrics["duration_ms"] = int((time.perf_counter() - step_started) * 1000)
                    context.outputs.setdefault("_step_metrics", {})[step.name] = dict(result.metrics)
                    artifacts.extend(result.artifacts)
                    summary["steps"].append({"name": step.name, "status": "success", "metrics": result.metrics})
                    summary["completed_steps"] = len(summary["steps"])
                    repo.create_task_run(conn, run_id=run_id, step_name=step.name, status="success", metrics=result.metrics)
                    summary["last_progress_at"] = utc_now()
                    if _is_run_running(conn, run_id):
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
                except _StepTimeout as exc:  # step 超时: 终态 interrupted, 遗弃的 daemon 线程会自灭
                    status = "interrupted"
                    error_message = str(exc)
                    summary["steps"].append({"name": step.name, "status": "interrupted", "error": error_message})
                    summary["completed_steps"] = len(summary["steps"])
                    repo.create_task_run(conn, run_id=run_id, step_name=step.name, status="interrupted", error_message=error_message)
                    break
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
            summary["last_progress_at"] = utc_now()
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


def _run_step_with_timeout(step: Any, context: PipelineContext, timeout: float) -> StepResult:
    """在 daemon 线程里跑 step, future.result(timeout=step_timeout) 硬限时。

    step 超过 step_timeout → 抛 _StepTimeout; 遗弃的 daemon 线程继续自跑(会自灭:
    下层 bounded_parallel 与网络层都已有硬超时), 其晚写只碰 summary_json、不碰 status。
    """
    future: concurrent.futures.Future[StepResult] = concurrent.futures.Future()

    def _wrap() -> None:
        try:
            future.set_result(step.run(context))
        except BaseException as exc:  # noqa: BLE001 - 线程隔离, 确保 runner 的 except Exception 能兜住
            future.set_exception(exc if isinstance(exc, Exception) else RuntimeError(f"step raised {type(exc).__name__}: {exc}"))

    thread = threading.Thread(target=_wrap, name=f"step-{getattr(step, 'name', '?')}", daemon=True)
    thread.start()
    try:
        return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        raise _StepTimeout(f"step {getattr(step, 'name', '?')} exceeded {timeout:g}s") from None


def _is_run_running(conn, run_id: str) -> bool:
    """DB status 是 run 的状态权威(与看门狗/回收共享)。"""
    row = conn.execute("SELECT status FROM pipeline_runs WHERE run_id = ?", (run_id,)).fetchone()
    return bool(row and row["status"] == "running")
