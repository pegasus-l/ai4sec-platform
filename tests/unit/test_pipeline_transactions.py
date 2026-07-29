from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ai4sec_platform.core.config import Settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.registry import PipelineRegistry
from ai4sec_platform.pipelines.runner import PipelineRunner


def _settings(tmp_path: Path) -> Settings:
    return Settings(project_root=tmp_path, output_dir=tmp_path / "output", database_path=tmp_path / "test.db")


def _runner(settings: Settings, step) -> PipelineRunner:
    registry = PipelineRegistry()
    registry.register(PipelineDefinition(name="test.transaction", domain="news", steps=[step]))
    return PipelineRunner(settings=settings, registry=registry)


@dataclass
class FailingAtomicStep:
    name: str = "failing_atomic"
    step_type: str = "test"

    def run(self, context):
        context.conn.execute(
            "INSERT INTO data_sources(domain, name, source_type, created_at) VALUES ('news', 'atomic-write', 'test', 'now')"
        )
        raise RuntimeError("planned atomic failure")


@dataclass
class CommittingAtomicStep:
    name: str = "committing_atomic"
    step_type: str = "test"

    def run(self, context):
        context.conn.execute(
            "INSERT INTO data_sources(domain, name, source_type, created_at) VALUES ('news', 'forbidden-commit', 'test', 'now')"
        )
        context.conn.commit()


@dataclass
class ArtifactThenFailStep:
    name: str = "artifact_then_fail"
    step_type: str = "test"

    def run(self, context):
        context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="failed_step_artifact",
            name="failed/should_be_removed.json",
            data={"temporary": True},
        )
        raise RuntimeError("planned artifact failure")


@dataclass
class FailingCheckpointedStep:
    name: str = "failing_checkpointed"
    step_type: str = "test"
    transaction_mode: str = "checkpointed"

    def run(self, context):
        context.conn.execute(
            "INSERT INTO data_sources(domain, name, source_type, created_at) VALUES ('news', 'durable-checkpoint', 'test', 'now')"
        )
        context.conn.commit()
        context.conn.execute(
            "INSERT INTO data_sources(domain, name, source_type, created_at) VALUES ('news', 'uncommitted-tail', 'test', 'now')"
        )
        raise RuntimeError("planned checkpointed failure")


def test_atomic_step_failure_rolls_back_business_writes(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    result = _runner(settings, FailingAtomicStep()).run("test.transaction", run_id="run_atomic_failure")

    assert result["status"] == "failed"
    assert result["summary"]["steps"][0]["transaction_mode"] == "atomic"
    with connect(settings) as conn:
        count = conn.execute("SELECT COUNT(*) FROM data_sources WHERE name = 'atomic-write'").fetchone()[0]
    assert count == 0


def test_atomic_step_cannot_commit_runner_transaction(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    result = _runner(settings, CommittingAtomicStep()).run("test.transaction", run_id="run_forbidden_commit")

    assert result["status"] == "failed"
    assert result["summary"]["steps"][0]["transaction_mode"] == "atomic"
    assert "must not commit" in result["summary"]["error_message"]
    with connect(settings) as conn:
        count = conn.execute("SELECT COUNT(*) FROM data_sources WHERE name = 'forbidden-commit'").fetchone()[0]
    assert count == 0


def test_atomic_step_failure_removes_uncommitted_artifact_file(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    failed_path = settings.output_dir / "shadow_runs" / "run_artifact_failure" / "failed" / "should_be_removed.json"

    result = _runner(settings, ArtifactThenFailStep()).run("test.transaction", run_id="run_artifact_failure")

    assert result["status"] == "failed"
    assert not failed_path.exists()
    with connect(settings) as conn:
        count = conn.execute(
            "SELECT COUNT(*) FROM artifacts WHERE run_id = ? AND artifact_type = 'failed_step_artifact'",
            ("run_artifact_failure",),
        ).fetchone()[0]
    assert count == 0


def test_checkpointed_step_keeps_committed_checkpoint_and_rolls_back_tail(tmp_path: Path) -> None:
    settings = _settings(tmp_path)

    result = _runner(settings, FailingCheckpointedStep()).run("test.transaction", run_id="run_checkpointed_failure")

    assert result["status"] == "failed"
    assert result["summary"]["steps"][0]["transaction_mode"] == "checkpointed"
    with connect(settings) as conn:
        names = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM data_sources WHERE name IN ('durable-checkpoint', 'uncommitted-tail')"
            ).fetchall()
        }
    assert names == {"durable-checkpoint"}
