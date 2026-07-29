from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, time, timedelta
import fcntl
import hashlib
from pathlib import Path
import time as clock
from typing import Any
from zoneinfo import ZoneInfo

import yaml

from ai4sec_platform.core.config import Settings, load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.jobs import JobConflictError, enqueue_job
from ai4sec_platform.pipelines.registry import PipelineRegistry, default_registry


class SchedulerAlreadyRunningError(RuntimeError):
    pass


@dataclass(frozen=True)
class Schedule:
    schedule_id: str
    pipeline_name: str
    daily_at: time
    grace_minutes: int
    enabled: bool = False
    weekdays: tuple[int, ...] = ()
    params: dict[str, Any] = field(default_factory=dict)
    reset_requested: bool = False


class PipelineScheduler:
    def __init__(self, settings: Settings | None = None, registry: PipelineRegistry | None = None, schedules: list[Schedule] | None = None, timezone_name: str | None = None) -> None:
        self.settings = settings or load_settings()
        self.registry = registry or default_registry()
        configured_timezone, configured_schedules = _load_schedule_config(self.settings.project_root / "configs" / "schedules.yaml")
        self.timezone = ZoneInfo(timezone_name or configured_timezone)
        self.schedules = schedules if schedules is not None else configured_schedules

    def tick(self, now: datetime | None = None) -> list[dict[str, str]]:
        current = (now or datetime.now(self.timezone)).astimezone(self.timezone)
        with self._scheduler_lock():
            outcomes: list[dict[str, str]] = []
            for schedule in self.schedules:
                if not schedule.enabled:
                    continue
                slot = _latest_due_slot(schedule, current)
                if slot is None or current - slot > timedelta(minutes=schedule.grace_minutes):
                    continue
                outcomes.append(self._enqueue_slot(schedule, slot))
            return outcomes

    def serve_forever(self, *, poll_interval: float = 30.0) -> None:
        with self._scheduler_lock():
            while True:
                self._tick_unlocked(datetime.now(self.timezone))
                clock.sleep(max(poll_interval, 1.0))

    def _tick_unlocked(self, current: datetime) -> list[dict[str, str]]:
        outcomes: list[dict[str, str]] = []
        for schedule in self.schedules:
            if not schedule.enabled:
                continue
            slot = _latest_due_slot(schedule, current)
            if slot is None or current - slot > timedelta(minutes=schedule.grace_minutes):
                continue
            outcomes.append(self._enqueue_slot(schedule, slot))
        return outcomes

    def _enqueue_slot(self, schedule: Schedule, slot: datetime) -> dict[str, str]:
        definition = self.registry.get(schedule.pipeline_name)
        run_id = _scheduled_run_id(schedule.schedule_id, slot)
        with connect(self.settings) as conn:
            init_db(conn)
            existing = conn.execute("SELECT status FROM pipeline_runs WHERE run_id = ?", (run_id,)).fetchone()
            if existing:
                return {"schedule_id": schedule.schedule_id, "run_id": run_id, "status": "already_enqueued"}
            try:
                enqueue_job(
                    conn,
                    run_id=run_id,
                    domain=definition.domain,
                    pipeline_name=definition.name,
                    params={**schedule.params, "_scheduled_for": slot.isoformat()},
                    total_steps=len(definition.steps),
                    reset_requested=schedule.reset_requested,
                )
            except JobConflictError:
                return {"schedule_id": schedule.schedule_id, "run_id": run_id, "status": "blocked"}
        return {"schedule_id": schedule.schedule_id, "run_id": run_id, "status": "queued"}

    def _scheduler_lock(self):
        return _ExclusiveFileLock(self.settings.output_dir / "locks" / "pipeline-scheduler.lock")


class _ExclusiveFileLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.handle = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.handle = self.path.open("a+", encoding="utf-8")
        try:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            self.handle.close()
            self.handle = None
            raise SchedulerAlreadyRunningError("another scheduler already holds the single-host lock") from exc
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.handle is not None:
            fcntl.flock(self.handle.fileno(), fcntl.LOCK_UN)
            self.handle.close()
            self.handle = None


def _load_schedule_config(path: Path) -> tuple[str, list[Schedule]]:
    if not path.exists():
        return "Asia/Shanghai", []
    payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    timezone_name = str(payload.get("timezone") or "Asia/Shanghai")
    schedules = [_parse_schedule(item) for item in payload.get("schedules", [])]
    return timezone_name, schedules


def _parse_schedule(raw: Any) -> Schedule:
    if not isinstance(raw, dict):
        raise ValueError("Each schedule must be a mapping")
    schedule_id = str(raw.get("id") or "").strip()
    pipeline_name = str(raw.get("pipeline_name") or "").strip()
    if not schedule_id or not pipeline_name:
        raise ValueError("Schedule requires id and pipeline_name")
    clock_value = str(raw.get("daily_at") or "").strip()
    try:
        hour, minute = (int(value) for value in clock_value.split(":"))
        daily_at = time(hour=hour, minute=minute)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid daily_at for schedule {schedule_id}: {clock_value}") from exc
    weekdays = tuple(sorted({int(value) for value in raw.get("weekdays", [])}))
    if any(value < 0 or value > 6 for value in weekdays):
        raise ValueError(f"Invalid weekdays for schedule {schedule_id}")
    grace_minutes = int(raw.get("grace_minutes", 60))
    if grace_minutes <= 0:
        raise ValueError(f"grace_minutes must be positive for schedule {schedule_id}")
    return Schedule(
        schedule_id=schedule_id,
        pipeline_name=pipeline_name,
        daily_at=daily_at,
        grace_minutes=grace_minutes,
        enabled=bool(raw.get("enabled", False)),
        weekdays=weekdays,
        params=dict(raw.get("params") or {}),
        reset_requested=bool(raw.get("reset", False)),
    )


def _latest_due_slot(schedule: Schedule, current: datetime) -> datetime | None:
    for offset in range(8):
        candidate_date = (current - timedelta(days=offset)).date()
        if schedule.weekdays and candidate_date.weekday() not in schedule.weekdays:
            continue
        slot = datetime.combine(candidate_date, schedule.daily_at, tzinfo=current.tzinfo)
        if slot <= current:
            return slot
    return None


def _scheduled_run_id(schedule_id: str, slot: datetime) -> str:
    digest = hashlib.sha256(schedule_id.encode("utf-8")).hexdigest()[:10]
    return f"scheduled_{digest}_{slot.strftime('%Y%m%dT%H%M%z')}"
