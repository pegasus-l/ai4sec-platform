from __future__ import annotations

import fcntl
from pathlib import Path
import threading
import time
from typing import Any, TextIO

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.core.ids import new_id
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.jobs import claim_next_job, finish_job, heartbeat_job, is_cancel_requested, reconcile_interrupted_jobs
from ai4sec_platform.pipelines.registry import PipelineRegistry, default_registry
from ai4sec_platform.pipelines.runner import PipelineRunner


class WorkerAlreadyRunningError(RuntimeError):
    pass


class PipelineWorker:
    def __init__(
        self,
        settings: Settings | None = None,
        registry: PipelineRegistry | None = None,
        *,
        worker_id: str | None = None,
        heartbeat_interval: float = 10.0,
    ) -> None:
        self.settings = settings or load_settings()
        self.registry = registry or default_registry()
        self.worker_id = worker_id or new_id("worker")
        self.heartbeat_interval = max(heartbeat_interval, 0.1)

    def recover(self) -> list[str]:
        with self._worker_lock():
            return self._recover()

    def _recover(self) -> list[str]:
        with connect(self.settings) as conn:
            init_db(conn)
            return reconcile_interrupted_jobs(conn)

    def run_once(self, *, run_id: str | None = None) -> dict[str, Any] | None:
        with self._worker_lock():
            return self._run_once(run_id=run_id)

    def _run_once(self, *, run_id: str | None = None) -> dict[str, Any] | None:
        with connect(self.settings) as conn:
            init_db(conn)
            job = claim_next_job(conn, worker_id=self.worker_id, run_id=run_id)
        if not job:
            return None
        try:
            with _JobHeartbeat(self, job["run_id"]):
                result = PipelineRunner(settings=self.settings, registry=self.registry).run(
                    job["pipeline_name"],
                    job["params"],
                    run_id=job["run_id"],
                    should_cancel=lambda: self._cancel_requested(job["run_id"]),
                )
            result_status = str(result.get("status") or "failed")
            status = result_status if result_status in {"success", "cancelled"} else "failed"
            error_message = str((result.get("summary") or {}).get("error_message") or "")
        except Exception as exc:
            status = "failed"
            error_message = str(exc)
            self._record_crash(job, error_message)
            result = {
                "run_id": job["run_id"],
                "pipeline_name": job["pipeline_name"],
                "domain": job["domain"],
                "status": "failed",
                "summary": {"params": job["params"], "status": "failed", "error_message": error_message},
            }
        with connect(self.settings) as conn:
            init_db(conn)
            finish_job(conn, run_id=job["run_id"], status=status, error_message=error_message)
        return result

    def _heartbeat(self, run_id: str) -> bool:
        with connect(self.settings) as conn:
            init_db(conn)
            return heartbeat_job(conn, run_id=run_id, worker_id=self.worker_id)

    def _cancel_requested(self, run_id: str) -> bool:
        with connect(self.settings) as conn:
            init_db(conn)
            return is_cancel_requested(conn, run_id)

    def serve_forever(self, *, poll_interval: float = 1.0) -> None:
        with self._worker_lock():
            self._recover()
            while True:
                result = self._run_once()
                if result is None:
                    time.sleep(poll_interval)

    def _record_crash(self, job: dict[str, Any], error_message: str) -> None:
        with connect(self.settings) as conn:
            init_db(conn)
            repo.create_pipeline_run(
                conn,
                run_id=job["run_id"],
                domain=job["domain"],
                pipeline_name=job["pipeline_name"],
                status="failed",
                started_at=job.get("started_at") or "",
                finished_at=utc_now(),
                production_writes=False,
                summary={"params": job["params"], "steps": [], "status": "failed", "error_message": error_message},
            )
            conn.commit()

    def _worker_lock(self):
        lock_path = self.settings.output_dir / "locks" / "pipeline-worker.lock"
        return _ExclusiveFileLock(lock_path)


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
            raise WorkerAlreadyRunningError("another pipeline worker already holds the single-host lock") from exc
        self.handle.seek(0)
        self.handle.truncate()
        self.handle.write(f"{new_id('worker_lock')}\n")
        self.handle.flush()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.handle is None:
            return
        fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
        self.handle.close()
        self.handle = None


class _JobHeartbeat:
    def __init__(self, worker: PipelineWorker, run_id: str) -> None:
        self.worker = worker
        self.run_id = run_id
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name=f"heartbeat-{run_id}", daemon=True)

    def __enter__(self) -> "_JobHeartbeat":
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.stop_event.set()
        self.thread.join(timeout=max(self.worker.heartbeat_interval * 2, 1.0))

    def _run(self) -> None:
        while not self.stop_event.wait(self.worker.heartbeat_interval):
            if not self.worker._heartbeat(self.run_id):
                return
