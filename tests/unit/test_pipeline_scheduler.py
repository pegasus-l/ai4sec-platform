from __future__ import annotations

from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

from ai4sec_platform.core.config import Settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.jobs import enqueue_job
from ai4sec_platform.pipelines.jobs import set_execution_kill_switch
from ai4sec_platform.pipelines.registry import PipelineRegistry
from ai4sec_platform.pipelines.scheduler import PipelineScheduler, Schedule, SchedulerAlreadyRunningError
from ai4sec_platform.pipelines.steps.audit import AuditStep


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "platform.db")


def _registry() -> PipelineRegistry:
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.scheduled", domain="news", steps=[AuditStep()]))
    return registry


def _schedule(**overrides) -> Schedule:
    values = {
        "schedule_id": "news-daily",
        "pipeline_name": "test.scheduled",
        "daily_at": time(6, 30),
        "grace_minutes": 120,
        "enabled": True,
    }
    values.update(overrides)
    return Schedule(**values)


def test_scheduler_queues_due_slot_once_across_restarts(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    schedule = _schedule()
    now = datetime(2026, 7, 29, 7, 0, tzinfo=ZoneInfo("Asia/Shanghai"))

    first = PipelineScheduler(settings=settings, registry=_registry(), schedules=[schedule]).tick(now)
    second = PipelineScheduler(settings=settings, registry=_registry(), schedules=[schedule]).tick(now)

    assert first[0]["status"] == "queued"
    assert second[0]["status"] == "already_enqueued"
    with connect(settings) as conn:
        count = conn.execute("SELECT COUNT(*) FROM pipeline_jobs").fetchone()[0]
        params = conn.execute("SELECT params_json FROM pipeline_jobs").fetchone()[0]
    assert count == 1
    assert "_scheduled_for" in params


def test_scheduler_skips_slot_after_misfire_grace(tmp_path: Path) -> None:
    schedule = _schedule(grace_minutes=30)
    now = datetime(2026, 7, 29, 7, 1, tzinfo=ZoneInfo("Asia/Shanghai"))

    outcomes = PipelineScheduler(settings=_settings(tmp_path), registry=_registry(), schedules=[schedule]).tick(now)

    assert outcomes == []


def test_scheduler_retries_blocked_slot_until_grace_expires(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with connect(settings) as conn:
        init_db(conn)
        enqueue_job(
            conn,
            run_id="manual-active",
            domain="news",
            pipeline_name="test.scheduled",
            params={},
            total_steps=1,
            reset_requested=False,
        )
    schedule = _schedule()
    scheduler = PipelineScheduler(settings=settings, registry=_registry(), schedules=[schedule])
    now = datetime(2026, 7, 29, 7, 0, tzinfo=ZoneInfo("Asia/Shanghai"))

    blocked = scheduler.tick(now)
    with connect(settings) as conn:
        conn.execute("UPDATE pipeline_jobs SET status = 'success' WHERE run_id = 'manual-active'")
        conn.commit()
    queued = scheduler.tick(now)

    assert blocked[0]["status"] == "blocked"
    assert queued[0]["status"] == "queued"


def test_scheduler_honors_weekday_schedule(tmp_path: Path) -> None:
    schedule = _schedule(weekdays=(0,))
    sunday = datetime(2026, 8, 2, 7, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
    monday = datetime(2026, 8, 3, 7, 0, tzinfo=ZoneInfo("Asia/Shanghai"))
    scheduler = PipelineScheduler(settings=_settings(tmp_path), registry=_registry(), schedules=[schedule])

    assert scheduler.tick(sunday) == []
    assert scheduler.tick(monday)[0]["status"] == "queued"


def test_scheduler_single_host_lock_rejects_second_instance(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    first = PipelineScheduler(settings=settings, registry=_registry(), schedules=[])
    second = PipelineScheduler(settings=settings, registry=_registry(), schedules=[])

    with first._scheduler_lock():
        try:
            with second._scheduler_lock():
                raise AssertionError("second scheduler acquired the lock")
        except SchedulerAlreadyRunningError:
            pass


def test_scheduler_reports_disabled_while_kill_switch_is_active(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    with connect(settings) as conn:
        init_db(conn)
        set_execution_kill_switch(conn, enabled=True, reason="maintenance")
    now = datetime(2026, 7, 29, 7, 0, tzinfo=ZoneInfo("Asia/Shanghai"))

    outcome = PipelineScheduler(settings=settings, registry=_registry(), schedules=[_schedule()]).tick(now)

    assert outcome[0]["status"] == "disabled"
