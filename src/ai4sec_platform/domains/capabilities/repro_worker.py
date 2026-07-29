from __future__ import annotations

import fcntl
import json
from pathlib import Path
import shutil
import time
from typing import Any, TextIO

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.core.ids import new_id
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities.adapters.repro_results import update_capability_from_report
from ai4sec_platform.domains.capabilities.adapters.repro_runner import ReproRunner, _safe_run, validate_repro_runtime_config
from ai4sec_platform.domains.capabilities.repro_jobs import (
    claim_cleanup_request,
    claim_next_repro_task,
    heartbeat_repro_task,
    is_repro_cancel_requested,
    reconcile_interrupted_repro_tasks,
)


class ReproWorkerAlreadyRunningError(RuntimeError):
    pass


class CapabilityReproWorker:
    def __init__(self, settings: Settings | None = None, *, worker_id: str | None = None) -> None:
        self.settings = settings or load_settings()
        self.worker_id = worker_id or new_id("repro-worker")

    def recover(self) -> list[int]:
        with self._worker_lock():
            return self._recover()

    def _recover(self) -> list[int]:
        with connect(self.settings) as conn:
            init_db(conn)
            interrupted = reconcile_interrupted_repro_tasks(conn)
        for task in interrupted:
            self._cleanup_resources(task)
        return [int(task["id"]) for task in interrupted]

    def run_once(self, *, task_id: int | None = None) -> dict[str, Any] | None:
        validate_repro_runtime_config(check_image=True)
        with self._worker_lock():
            return self._run_once(task_id=task_id)

    def _run_once(self, *, task_id: int | None = None) -> dict[str, Any] | None:
        cleanup = self._claim_cleanup(task_id=task_id)
        if cleanup:
            self._finish_cleanup(cleanup)
            return {"task_id": cleanup["id"], "status": "cleaned"}
        with connect(self.settings) as conn:
            init_db(conn)
            task = claim_next_repro_task(conn, worker_id=self.worker_id, task_id=task_id)
        if not task:
            return None
        try:
            self._run_task(task)
        except Exception as exc:
            self._fail_task(task, exc)
        cleanup = self._claim_cleanup(task_id=int(task["id"]))
        if cleanup:
            self._finish_cleanup(cleanup)
        with connect(self.settings) as conn:
            init_db(conn)
            return repo.get_repro_task(conn, int(task["id"]))

    def serve_forever(self, *, poll_interval: float = 1.0) -> None:
        validate_repro_runtime_config(check_image=True)
        with self._worker_lock():
            self._recover()
            while True:
                if self._run_once() is None:
                    time.sleep(poll_interval)

    def _run_task(self, task: dict[str, Any]) -> None:
        task_id = int(task["id"])
        last_heartbeat = 0.0

        def on_log(line: str) -> None:
            with connect(self.settings) as conn:
                init_db(conn)
                repo.append_repro_log(conn, task_id=task_id, line=line)
                conn.commit()

        def on_status(status: str, **values: Any) -> None:
            fields: dict[str, Any] = {"status": status}
            if "result" in values:
                fields["result"] = str(values["result"])[:10000]
            if status in {"success", "partial", "failed", "timeout", "stopped"}:
                fields["finished_at"] = utc_now()
                fields["worker_id"] = ""
                fields["heartbeat_at"] = ""
            report = values.get("report")
            if report:
                fields["report_json"] = json.dumps(report, ensure_ascii=False) if isinstance(report, dict) else str(report)
            if "web_port" in values:
                fields["web_port"] = values["web_port"]
            if "web_url" in values:
                fields["web_url"] = values["web_url"]
            with connect(self.settings) as conn:
                init_db(conn)
                repo.update_repro_task(conn, task_id=task_id, **fields)
                if report:
                    update_capability_from_report(conn, item_id=int(task["item_id"]), report=report)
                conn.commit()

        def should_stop() -> bool:
            with connect(self.settings) as conn:
                init_db(conn)
                return is_repro_cancel_requested(conn, task_id)

        def heartbeat() -> None:
            nonlocal last_heartbeat
            now = time.monotonic()
            if now - last_heartbeat < 10:
                return
            with connect(self.settings) as conn:
                init_db(conn)
                heartbeat_repro_task(conn, task_id=task_id, worker_id=self.worker_id)
            last_heartbeat = now

        runner = ReproRunner(
            task_id=task_id,
            repo_url=str(task["repo_url"]),
            on_log=on_log,
            on_status=on_status,
            web_port=task.get("web_port"),
            should_stop=should_stop,
            on_heartbeat=heartbeat,
        )
        with connect(self.settings) as conn:
            init_db(conn)
            repo.update_repro_task(
                conn,
                task_id=task_id,
                container_name=runner.container_name,
                workspace_path=str(runner.workspace),
            )
            conn.commit()
        runner.run()

    def _fail_task(self, task: dict[str, Any], error: Exception) -> None:
        with connect(self.settings) as conn:
            init_db(conn)
            repo.update_repro_task(
                conn,
                task_id=int(task["id"]),
                status="failed",
                result=f"repro worker error: {error}"[:10000],
                finished_at=utc_now(),
                worker_id="",
                heartbeat_at="",
            )
            conn.commit()

    def _claim_cleanup(self, *, task_id: int | None = None) -> dict[str, Any] | None:
        with connect(self.settings) as conn:
            init_db(conn)
            return claim_cleanup_request(conn, task_id=task_id)

    def _finish_cleanup(self, task: dict[str, Any]) -> None:
        self._cleanup_resources(task)
        with connect(self.settings) as conn:
            init_db(conn)
            repo.update_repro_task(
                conn,
                task_id=int(task["id"]),
                status="cleaned",
                cleaned_at=utc_now(),
                cleanup_requested=0,
                worker_id="",
                heartbeat_at="",
            )
            conn.commit()

    @staticmethod
    def _cleanup_resources(task: dict[str, Any]) -> None:
        container_name = str(task.get("container_name") or "")
        if container_name:
            _safe_run(["docker", "rm", "-f", container_name], capture_output=True)
        workspace_path = str(task.get("workspace_path") or "")
        if workspace_path:
            workspace = Path(workspace_path)
            if workspace.exists():
                shutil.rmtree(workspace, ignore_errors=True)

    def _worker_lock(self) -> "_ExclusiveFileLock":
        return _ExclusiveFileLock(self.settings.output_dir / "locks" / "capability-repro-worker.lock")


class _ExclusiveFileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle: TextIO | None = None

    def __enter__(self) -> "_ExclusiveFileLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.handle.close()
            self.handle = None
            raise ReproWorkerAlreadyRunningError("capability repro worker is already running") from exc
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.handle is None:
            return
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        self.handle.close()
        self.handle = None
