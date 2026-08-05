from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import shutil
import socket
import secrets
import stat
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
    REPRO_DOCKER_LABEL_OWNER,
    REPRO_DOCKER_LABEL_PROFILE,
    REPRO_DOCKER_LABEL_RESOURCE,
    REPRO_DOCKER_LABEL_TASK,
    REPRO_DOCKER_RESOURCE,
    WORKSPACE_ROOT,
    _safe_run,
    enforce_report_acceptance,
    extract_report,
    managed_opencode_config,
    task_status_from_report,
    validate_repro_runtime_config,
)
from ai4sec_platform.domains.capabilities.egress_approvals import approved_egress_domains
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
from ai4sec_platform.domains.capabilities.repro_profiles import REPRO_EXECUTION_PROFILES
from ai4sec_platform.pipelines.jobs import is_execution_kill_switch_active


def repro_runtime_secret_dir() -> Path:
    configured = os.environ.get("AI4SEC_RUNTIME_SECRET_DIR", "").strip()
    root = Path(configured).expanduser() if configured else Path(f"/tmp/ai4sec-runtime-{os.getuid()}")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    file_stat = root.lstat()
    if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISDIR(file_stat.st_mode):
        raise RuntimeError("AI4SEC runtime secret directory must be a regular non-symlink directory")
    if file_stat.st_uid != os.getuid() or file_stat.st_mode & 0o077:
        raise RuntimeError("AI4SEC runtime secret directory must be owned by the Worker and mode 0700")
    return root


class ReproWorkerAlreadyRunningError(RuntimeError):
    pass


class CapabilityReproWorker:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        worker_id: str | None = None,
        execution_profile: str = "standard",
    ) -> None:
        if execution_profile not in REPRO_EXECUTION_PROFILES:
            raise ValueError(f"unknown reproduction execution profile: {execution_profile}")
        self.settings = settings or load_settings()
        self.execution_profile = execution_profile
        self.worker_id = worker_id or new_id(f"repro-{execution_profile}-worker")
        self.runtime_owner_id = hashlib.sha256(
            str(self.settings.database_path.expanduser().resolve()).encode("utf-8")
        ).hexdigest()[:24]
        self._last_worker_heartbeat = 0.0

    def recover(self) -> list[int]:
        with self._worker_lock():
            self._register()
            try:
                return self._recover()
            finally:
                self._stop()

    def _recover(self) -> list[int]:
        self._reconcile_managed_orphans()
        with connect(self.settings) as conn:
            init_db(conn)
            running = [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM capability_repro_tasks "
                    "WHERE status = 'running' AND execution_profile = ? ORDER BY id",
                    (self.execution_profile,),
                ).fetchall()
            ]
            outcomes = {int(task["id"]): self._recovery_outcome(task) for task in running}
            interrupted = reconcile_interrupted_repro_tasks(
                conn,
                recovered_outcomes=outcomes,
                execution_profile=self.execution_profile,
            )
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
        validate_repro_runtime_config(
            check_image=True,
            require_token=False,
            execution_profile=self.execution_profile,
        )
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
            task = claim_next_repro_task(
                conn,
                worker_id=self.worker_id,
                task_id=task_id,
                execution_profile=self.execution_profile,
            )
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
        validate_repro_runtime_config(
            check_image=True,
            require_token=False,
            execution_profile=self.execution_profile,
        )
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
        repro_strategy = str(task.get("repro_strategy") or "cli")
        if repro_strategy == "local_web" and not task.get("web_port"):
            raise RuntimeError("local_web reproduction task is missing its reserved loopback port")
        if repro_strategy == "cli" and task.get("web_port"):
            raise RuntimeError("cli reproduction task must not reserve a Web port")
        last_heartbeat = 0.0
        with connect(self.settings) as conn:
            init_db(conn)
            task_egress_domains = approved_egress_domains(conn, task_id=task_id)

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

        def on_runtime(**values: Any) -> None:
            allowed = {key: values[key] for key in ("container_id", "proxy_pid") if key in values}
            if not allowed:
                return
            with connect(self.settings) as conn:
                init_db(conn)
                repo.update_repro_task(conn, task_id=task_id, **allowed)
                conn.commit()

        token_path = self._issue_model_token(task_id)
        managed_config_path = token_path.with_suffix(".opencode.json")
        try:
            self._write_managed_config(managed_config_path)
            runner = ReproRunner(
                task_id=task_id,
                repo_url=str(task["repo_url"]),
                repo_commit=str(task.get("repo_commit") or ""),
                on_log=on_log,
                on_status=on_status,
                web_port=task.get("web_port"),
                should_stop=should_stop,
                on_heartbeat=heartbeat,
                model_token_path=token_path,
                approved_egress_domains=task_egress_domains,
                execution_profile=self.execution_profile,
                managed_config_path=managed_config_path,
                runtime_owner_id=self.runtime_owner_id,
                on_runtime=on_runtime,
            )
            with connect(self.settings) as conn:
                init_db(conn)
                repo.update_repro_task(
                    conn,
                    task_id=task_id,
                    container_name=runner.container_name,
                    workspace_path=str(runner.workspace),
                    runtime_owner_id=self.runtime_owner_id,
                )
                conn.commit()
            runner.run()
        finally:
            with connect(self.settings) as conn:
                init_db(conn)
                revoke_task_model_tokens(conn, task_id=task_id)
                conn.commit()
            token_path.unlink(missing_ok=True)
            managed_config_path.unlink(missing_ok=True)

    def _write_managed_config(self, config_path: Path) -> None:
        descriptor = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as config_file:
                json.dump(managed_opencode_config(self.execution_profile), config_file, ensure_ascii=False)
        except Exception:
            config_path.unlink(missing_ok=True)
            raise

    def _issue_model_token(self, task_id: int) -> Path:
        secret_dir = repro_runtime_secret_dir() / "repro"
        secret_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        secret_dir.chmod(0o700)
        file_stat = secret_dir.lstat()
        if stat.S_ISLNK(file_stat.st_mode) or not stat.S_ISDIR(file_stat.st_mode) or file_stat.st_uid != os.getuid() or file_stat.st_mode & 0o077:
            raise RuntimeError("AI4SEC repro secret directory must be owned by the Worker and mode 0700")
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
            return claim_cleanup_request(
                conn,
                task_id=task_id,
                execution_profile=self.execution_profile,
            )

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

    def _recovery_outcome(self, task: dict[str, Any]) -> dict[str, Any]:
        report = enforce_report_acceptance(extract_report(str(task.get("log") or "")))
        if report:
            return {
                "status": task_status_from_report(report),
                "result": "recovered completed report after repro worker interruption",
                "report": report,
                "report_json": json.dumps(report, ensure_ascii=False),
            }
        container_ref = str(task.get("container_id") or task.get("container_name") or "")
        inspected = self._inspect_container(container_ref)
        container_alive = bool(
            inspected
            and self._container_belongs_to_task(inspected, task)
            and inspected.get("State", {}).get("Running") is True
        )
        detail = "running orphan container found and scheduled for cleanup" if container_alive else "no running container found"
        return {
            "status": "failed",
            "result": f"repro worker interrupted; {detail}; task was not replayed automatically",
        }

    def _cleanup_resources(self, task: dict[str, Any]) -> None:
        task_id = int(task["id"])
        with connect(self.settings) as conn:
            init_db(conn)
            revoke_task_model_tokens(conn, task_id=task_id)
            conn.commit()
        self._remove_task_runtime_secrets(task_id)
        self._stop_persisted_proxy(task)
        container_name = str(task.get("container_name") or "")
        container_id = str(task.get("container_id") or "")
        container_ref = container_id or container_name
        if container_ref:
            inspected = self._inspect_container(container_ref)
            if inspected and self._container_belongs_to_task(inspected, task):
                _safe_run(["docker", "rm", "-f", str(inspected["Id"])], capture_output=True)
        workspace_path = str(task.get("workspace_path") or "")
        if workspace_path:
            workspace = Path(workspace_path).expanduser().resolve()
            workspace_root = WORKSPACE_ROOT.expanduser().resolve()
            if workspace != workspace_root and workspace.is_relative_to(workspace_root) and workspace.exists():
                shutil.rmtree(workspace, ignore_errors=True)

    @staticmethod
    def _remove_task_runtime_secrets(task_id: int) -> None:
        secret_dir = repro_runtime_secret_dir() / "repro"
        try:
            directory_stat = secret_dir.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(directory_stat.st_mode) or not stat.S_ISDIR(directory_stat.st_mode):
            raise RuntimeError("AI4SEC repro secret directory must be a regular non-symlink directory")
        if directory_stat.st_uid != os.getuid() or directory_stat.st_mode & 0o077:
            raise RuntimeError("AI4SEC repro secret directory must be owned by the Worker and mode 0700")
        prefix = f"task-{task_id}-"
        for path in secret_dir.iterdir():
            if not path.name.startswith(prefix) or not path.name.endswith((".token", ".opencode.json")):
                continue
            file_stat = path.lstat()
            if file_stat.st_uid != os.getuid():
                continue
            if stat.S_ISREG(file_stat.st_mode) or stat.S_ISLNK(file_stat.st_mode):
                path.unlink(missing_ok=True)

    def _reconcile_managed_orphans(self) -> list[str]:
        listed = _safe_run(
            [
                "docker", "ps", "-aq",
                "--filter", f"label={REPRO_DOCKER_LABEL_RESOURCE}={REPRO_DOCKER_RESOURCE}",
                "--filter", f"label={REPRO_DOCKER_LABEL_OWNER}={self.runtime_owner_id}",
                "--filter", f"label={REPRO_DOCKER_LABEL_PROFILE}={self.execution_profile}",
            ],
            capture_output=True,
            text=True,
        )
        if getattr(listed, "returncode", 1) != 0:
            return []
        removed: list[str] = []
        with connect(self.settings) as conn:
            init_db(conn)
            for container_ref in str(listed.stdout or "").splitlines():
                inspected = self._inspect_container(container_ref.strip())
                if not inspected:
                    continue
                labels = inspected.get("Config", {}).get("Labels") or {}
                if not self._container_has_runtime_scope(labels):
                    continue
                try:
                    task_id = int(labels.get(REPRO_DOCKER_LABEL_TASK, ""))
                except ValueError:
                    task_id = 0
                task = repo.get_repro_task(conn, task_id) if task_id else None
                container_name = str(inspected.get("Name") or "").removeprefix("/")
                container_id = str(inspected.get("Id") or "")
                is_current = bool(
                    task
                    and str(task.get("runtime_owner_id") or "") == self.runtime_owner_id
                    and str(task.get("container_name") or "") == container_name
                    and (not task.get("container_id") or str(task["container_id"]) == container_id)
                    and str(task.get("status") or "") != "cleaned"
                )
                if is_current:
                    continue
                if not container_id:
                    continue
                deleted = _safe_run(["docker", "rm", "-f", container_id], capture_output=True)
                if getattr(deleted, "returncode", 1) == 0:
                    removed.append(container_id)
        return removed

    @staticmethod
    def _inspect_container(container_ref: str) -> dict[str, Any] | None:
        if not container_ref:
            return None
        inspected = _safe_run(["docker", "inspect", container_ref], capture_output=True, text=True)
        if getattr(inspected, "returncode", 1) != 0:
            return None
        try:
            payload = json.loads(str(inspected.stdout or ""))
        except json.JSONDecodeError:
            return None
        return payload[0] if isinstance(payload, list) and payload and isinstance(payload[0], dict) else None

    def _container_belongs_to_task(self, inspected: dict[str, Any], task: dict[str, Any]) -> bool:
        labels = inspected.get("Config", {}).get("Labels") or {}
        return bool(
            self._container_has_runtime_scope(labels)
            and labels.get(REPRO_DOCKER_LABEL_TASK) == str(task.get("id"))
            and str(task.get("runtime_owner_id") or "") == self.runtime_owner_id
        )

    def _container_has_runtime_scope(self, labels: dict[str, Any]) -> bool:
        return bool(
            labels.get(REPRO_DOCKER_LABEL_RESOURCE) == REPRO_DOCKER_RESOURCE
            and labels.get(REPRO_DOCKER_LABEL_OWNER) == self.runtime_owner_id
            and labels.get(REPRO_DOCKER_LABEL_PROFILE) == self.execution_profile
        )

    @staticmethod
    def _stop_persisted_proxy(task: dict[str, Any]) -> None:
        proxy_pid = int(task.get("proxy_pid") or 0)
        web_port = int(task.get("web_port") or 0)
        if proxy_pid <= 1 or web_port <= 0:
            return
        try:
            command = Path(f"/proc/{proxy_pid}/cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace")
        except OSError:
            return
        if "socat" not in command or f"TCP-LISTEN:{web_port},bind=127.0.0.1" not in command:
            return
        try:
            os.kill(proxy_pid, signal.SIGTERM)
        except ProcessLookupError:
            return

    def _worker_lock(self) -> "_ExclusiveFileLock":
        return _ExclusiveFileLock(
            self.settings.output_dir / "locks" / f"capability-repro-{self.execution_profile}-worker.lock"
        )

    def _register(self) -> None:
        with connect(self.settings) as conn:
            init_db(conn)
            register_repro_worker(
                conn,
                worker_id=self.worker_id,
                hostname=socket.gethostname(),
                pid=os.getpid(),
                metadata={
                    "kind": "capability_repro",
                    "execution": "single_host",
                    "profile": self.execution_profile,
                },
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
