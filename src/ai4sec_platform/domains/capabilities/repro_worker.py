from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import secrets
import time
from typing import Any, TextIO

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.core.ids import new_id
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities.adapters.repro_results import update_capability_from_report
from ai4sec_platform.domains.capabilities.adapters.repro_runner import (
    ReproRunner,
    _safe_run,
    enforce_report_acceptance,
    extract_report,
    task_status_from_report,
    validate_repro_runtime_config,
)
from ai4sec_platform.domains.capabilities.repro_jobs import (
    REPRO_TERMINAL_STATUSES,
    claim_cleanup_request,
    claim_next_repro_task,
    heartbeat_repro_task,
    heartbeat_repro_worker,
    is_repro_cancel_requested,
    reconcile_interrupted_repro_tasks,
    register_repro_worker,
    stop_repro_worker,
    transition_repro_task,
)
from ai4sec_platform.domains.capabilities.model_gateway import issue_task_model_token, revoke_task_model_tokens
from ai4sec_platform.domains.capabilities.repro_policy import REPRO_WORKER_HEARTBEAT_SECONDS
from ai4sec_platform.pipelines.jobs import is_execution_kill_switch_active


class ReproWorkerAlreadyRunningError(RuntimeError):
    pass


class CapabilityReproWorker:
    def __init__(self, settings: Settings | None = None, *, worker_id: str | None = None) -> None:
        self.settings = settings or load_settings()
        self.worker_id = worker_id or new_id("repro-worker")
        self._last_worker_heartbeat = 0.0

    def recover(self) -> list[int]:
        with self._worker_lock():
            self._register()
            try:
                return self._recover()
            finally:
                self._stop()

    def _recover(self) -> list[int]:
        with connect(self.settings) as conn:
            init_db(conn)
            running = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM capability_repro_tasks WHERE status = 'running' ORDER BY id"
                ).fetchall()
            ]
            outcomes = {int(task["id"]): self._recovery_outcome(task) for task in running}
            interrupted = reconcile_interrupted_repro_tasks(conn, recovered_outcomes=outcomes)
            for task in interrupted:
                outcome = outcomes[int(task["id"])]
                report = outcome.get("report")
                if report:
                    update_capability_from_report(conn, item_id=int(task["item_id"]), report=report)
            conn.commit()
        for task in interrupted:
            self._cleanup_resources(task)
        return [int(task["id"]) for task in interrupted]

    def run_once(self, *, task_id: int | None = None) -> dict[str, Any] | None:
        validate_repro_runtime_config(check_image=True, require_token=False)
        with self._worker_lock():
            self._register()
            try:
                return self._run_once(task_id=task_id)
            finally:
                self._stop()

    def _run_once(self, *, task_id: int | None = None) -> dict[str, Any] | None:
        cleanup = self._claim_cleanup(task_id=task_id)
        if cleanup:
            self._finish_cleanup(cleanup)
            return {"task_id": cleanup["id"], "status": "cleaned"}
        with connect(self.settings) as conn:
            init_db(conn)
            task = claim_next_repro_task(conn, worker_id=self.worker_id, task_id=task_id)
        if not task:
            self._heartbeat_worker()
            return None
        self._heartbeat_worker(current_task_id=int(task["id"]), force=True)
        try:
            self._run_task(task)
        except Exception as exc:
            self._fail_task(task, exc)
        cleanup = self._claim_cleanup(task_id=int(task["id"]))
        if cleanup:
            self._finish_cleanup(cleanup)
        with connect(self.settings) as conn:
            init_db(conn)
            result = repo.get_repro_task(conn, int(task["id"]))
        self._heartbeat_worker(force=True)
        return result

    def serve_forever(self, *, poll_interval: float = 1.0) -> None:
        validate_repro_runtime_config(check_image=True, require_token=False)
        with self._worker_lock():
            self._register()
            try:
                self._recover()
                while True:
                    if self._run_once() is None:
                        time.sleep(poll_interval)
            finally:
                self._stop()

    def _run_task(self, task: dict[str, Any]) -> None:
        task_id = int(task["id"])
        last_heartbeat = 0.0

        def on_log(line: str) -> None:
            with connect(self.settings) as conn:
                init_db(conn)
                repo.append_repro_log(conn, task_id=task_id, line=line)
                conn.commit()

        def on_status(status: str, **values: Any) -> None:
            fields: dict[str, Any] = {}
            if "result" in values:
                fields["result"] = str(values["result"])[:10000]
            if status in REPRO_TERMINAL_STATUSES:
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
                transition_repro_task(conn, task_id=task_id, status=status, fields=fields)
                if report:
                    update_capability_from_report(conn, item_id=int(task["item_id"]), report=report)
                conn.commit()

        def should_stop() -> bool:
            with connect(self.settings) as conn:
                init_db(conn)
                return is_repro_cancel_requested(conn, task_id) or is_execution_kill_switch_active(conn)

        def heartbeat() -> None:
            nonlocal last_heartbeat
            now = time.monotonic()
            if now - last_heartbeat < 10:
                return
            with connect(self.settings) as conn:
                init_db(conn)
                heartbeat_repro_task(conn, task_id=task_id, worker_id=self.worker_id)
                heartbeat_repro_worker(conn, worker_id=self.worker_id, current_task_id=task_id)
            last_heartbeat = now

        token_path = self._issue_model_token(task_id)
        try:
            runner = ReproRunner(
                task_id=task_id,
                repo_url=str(task["repo_url"]),
                on_log=on_log,
                on_status=on_status,
                web_port=task.get("web_port"),
                should_stop=should_stop,
                on_heartbeat=heartbeat,
                model_token_path=token_path,
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
        finally:
            with connect(self.settings) as conn:
                init_db(conn)
                revoke_task_model_tokens(conn, task_id=task_id)
                conn.commit()
            token_path.unlink(missing_ok=True)

    def _issue_model_token(self, task_id: int) -> Path:
        secret_dir = self.settings.output_dir / "runtime_secrets" / "repro"
        secret_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        secret_dir.chmod(0o700)
        with connect(self.settings) as conn:
            init_db(conn)
            token = issue_task_model_token(
                conn,
                task_id=task_id,
                model=os.getenv("REPRO_LLM_MODEL", "glm-5.2"),
                ttl_seconds=min(14_400, max(300, int(os.getenv("REPRO_MODEL_TOKEN_TTL_SECONDS", "4200")))),
                max_calls=max(1, int(os.getenv("REPRO_MODEL_MAX_CALLS", "200"))),
                max_tokens=max(1_000, int(os.getenv("REPRO_MODEL_MAX_TOKENS", "1000000"))),
            )
            conn.commit()
        token_path = secret_dir / f"task-{task_id}-{secrets.token_hex(8)}.token"
        try:
            descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as token_file:
                token_file.write(token)
            return token_path
        except Exception:
            with connect(self.settings) as conn:
                init_db(conn)
                revoke_task_model_tokens(conn, task_id=task_id)
                conn.commit()
            token_path.unlink(missing_ok=True)
            raise

    def _fail_task(self, task: dict[str, Any], error: Exception) -> None:
        with connect(self.settings) as conn:
            init_db(conn)
            transition_repro_task(
                conn,
                task_id=int(task["id"]),
                status="failed",
                fields={
                    "result": f"repro worker error: {error}"[:10000],
                    "finished_at": utc_now(),
                    "worker_id": "",
                    "heartbeat_at": "",
                },
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
            transition_repro_task(
                conn,
                task_id=int(task["id"]),
                status="cleaned",
                fields={
                    "cleaned_at": utc_now(),
                    "cleanup_requested": 0,
                    "worker_id": "",
                    "heartbeat_at": "",
                },
            )
            conn.commit()

    @staticmethod
    def _recovery_outcome(task: dict[str, Any]) -> dict[str, Any]:
        report = enforce_report_acceptance(extract_report(str(task.get("log") or "")))
        if report:
            return {
                "status": task_status_from_report(report),
                "result": "recovered completed report after repro worker interruption",
                "report": report,
                "report_json": json.dumps(report, ensure_ascii=False),
            }
        container_name = str(task.get("container_name") or "")
        container_alive = False
        if container_name:
            try:
                inspected = _safe_run(
                    ["docker", "inspect", "--format", "{{.State.Running}}", container_name],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                container_alive = inspected.returncode == 0 and str(inspected.stdout).strip().lower() == "true"
            except (OSError, subprocess.TimeoutExpired):
                container_alive = False
        detail = "running orphan container found and scheduled for cleanup" if container_alive else "no running container found"
        return {
            "status": "failed",
            "result": f"repro worker interrupted; {detail}; task was not replayed automatically",
        }

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

    def _register(self) -> None:
        with connect(self.settings) as conn:
            init_db(conn)
            register_repro_worker(
                conn,
                worker_id=self.worker_id,
                hostname=socket.gethostname(),
                pid=os.getpid(),
                metadata={"kind": "capability_repro", "execution": "single_host"},
            )
        self._last_worker_heartbeat = time.monotonic()

    def _heartbeat_worker(self, current_task_id: int | None = None, *, force: bool = False) -> bool:
        now = time.monotonic()
        if not force and now - self._last_worker_heartbeat < REPRO_WORKER_HEARTBEAT_SECONDS:
            return True
        with connect(self.settings) as conn:
            init_db(conn)
            updated = heartbeat_repro_worker(
                conn,
                worker_id=self.worker_id,
                current_task_id=current_task_id,
            )
        if updated:
            self._last_worker_heartbeat = now
        return updated

    def _stop(self) -> None:
        with connect(self.settings) as conn:
            init_db(conn)
            stop_repro_worker(conn, worker_id=self.worker_id)


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
