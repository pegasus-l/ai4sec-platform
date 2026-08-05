from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai4sec_platform.cli import repro_regression
from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.repro_policy import enqueue_repro_task
from ai4sec_platform.db.session import connect


def _manifest(tmp_path: Path) -> Path:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps({
        "samples": [{
            "sample_id": "python-cli-click",
            "repository_url": "https://github.com/pallets/click",
            "commit_sha": "a" * 40,
            "strategy": "cli",
            "expected_capability": "execute a minimal Click command",
        }],
    }), encoding="utf-8")
    return path


def test_regression_cli_refuses_platform_database(monkeypatch, tmp_path: Path) -> None:
    settings = Settings(
        project_root=tmp_path,
        output_dir=tmp_path / "output",
        database_path=tmp_path / "output" / "ai4sec_platform.db",
    )
    monkeypatch.setenv("AI4SEC_REPRO_REGRESSION_CONFIRM", "isolated-regression")

    with pytest.raises(RuntimeError, match="repro-regression directory"):
        repro_regression.validate_regression_settings(settings)


def test_prepare_creates_pinned_approved_tasks_in_isolated_database(monkeypatch, tmp_path: Path) -> None:
    output_dir = tmp_path / "repro-regression"
    settings = Settings(
        project_root=tmp_path,
        output_dir=output_dir,
        database_path=output_dir / "ai4sec_platform.db",
    )
    monkeypatch.setenv("AI4SEC_REPRO_REGRESSION_CONFIRM", "isolated-regression")
    monkeypatch.setattr(repro_regression, "load_settings", lambda: settings)

    result = repro_regression.prepare(_manifest(tmp_path))

    assert result["sample_count"] == 1
    with connect(settings) as conn:
        task = repo.get_repro_task(conn, result["task_ids"][0])
    assert task and task["status"] == "queued"
    assert task["repo_commit"] == "a" * 40
    assert task["execution_profile"] == "nested_docker"
    assert task["profile_approval_status"] == "approved"


def test_manifest_rejects_mutable_ref(tmp_path: Path) -> None:
    path = _manifest(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["samples"][0]["commit_sha"] = "main"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="40-character commit SHA"):
        repro_regression.load_manifest(path)


def test_report_uses_latest_attempt_regardless_of_trigger(monkeypatch, tmp_path: Path) -> None:
    output_dir = tmp_path / "repro-regression"
    settings = Settings(
        project_root=tmp_path,
        output_dir=output_dir,
        database_path=output_dir / "ai4sec_platform.db",
    )
    monkeypatch.setenv("AI4SEC_REPRO_REGRESSION_CONFIRM", "isolated-regression")
    monkeypatch.setattr(repro_regression, "load_settings", lambda: settings)
    prepared = repro_regression.prepare(_manifest(tmp_path))

    with connect(settings) as conn:
        first_task_id = prepared["task_ids"][0]
        first_task = repo.get_repro_task(conn, first_task_id)
        repo.update_repro_task(conn, task_id=first_task_id, status="failed", result="old failure")
        latest_task_id = enqueue_repro_task(
            conn,
            item_id=int(first_task["item_id"]),
            repo_url=str(first_task["repo_url"]),
            repo_commit=str(first_task["repo_commit"]),
            trigger="manual",
            initial_status="queued",
            execution_profile="nested_docker",
            repro_strategy="cli",
        )
        repo.update_repro_task(conn, task_id=latest_task_id, status="partial", result="latest result")
        conn.commit()

    result = repro_regression.report(_manifest(tmp_path))

    assert result["counts"] == {"partial": 1}
    assert result["items"][0]["task_id"] == latest_task_id
    assert result["items"][0]["attempt_count"] == 2
    assert result["items"][0]["result"] == "latest result"


def test_report_filters_other_manifests_and_preserves_cleaned_outcome(monkeypatch, tmp_path: Path) -> None:
    output_dir = tmp_path / "repro-regression"
    settings = Settings(
        project_root=tmp_path,
        output_dir=output_dir,
        database_path=output_dir / "ai4sec_platform.db",
    )
    monkeypatch.setenv("AI4SEC_REPRO_REGRESSION_CONFIRM", "isolated-regression")
    monkeypatch.setattr(repro_regression, "load_settings", lambda: settings)
    prepared = repro_regression.prepare(_manifest(tmp_path))

    with connect(settings) as conn:
        task_id = prepared["task_ids"][0]
        repo.update_repro_task(
            conn,
            task_id=task_id,
            status="cleaned",
            report_json=json.dumps({"status": "success"}),
        )
        other_item_id = repo.create_domain_item(
            conn,
            domain="capabilities",
            item_type="capability",
            title="Regression: excluded-sample",
            summary="Other manifest sample",
            source="capability_repro_regression",
            payload={"regression_sample_id": "excluded-sample"},
        )
        other_task_id = enqueue_repro_task(
            conn,
            item_id=other_item_id,
            repo_url="https://github.com/example/excluded",
            repo_commit="b" * 40,
            trigger="capability_repro_regression",
            initial_status="queued",
            execution_profile="nested_docker",
            repro_strategy="cli",
        )
        repo.update_repro_task(conn, task_id=other_task_id, status="failed")
        conn.commit()

    result = repro_regression.report(_manifest(tmp_path))

    assert result["counts"] == {"success": 1}
    assert result["items"] == [
        {
            "sample_id": "python-cli-click",
            "task_id": prepared["task_ids"][0],
            "attempt_count": 1,
            "repo_commit": "a" * 40,
            "status": "success",
            "lifecycle_status": "cleaned",
            "result": "",
            "expected_capability": "execute a minimal Click command",
        }
    ]


def test_prepare_allocates_port_for_local_web_sample(monkeypatch, tmp_path: Path) -> None:
    output_dir = tmp_path / "repro-regression"
    settings = Settings(project_root=tmp_path, output_dir=output_dir, database_path=output_dir / "ai4sec_platform.db")
    manifest = _manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["samples"][0]["strategy"] = "local_web"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("AI4SEC_REPRO_REGRESSION_CONFIRM", "isolated-regression")
    monkeypatch.setattr(repro_regression, "load_settings", lambda: settings)
    monkeypatch.setattr(repro_regression, "allocate_repro_web_port", lambda _conn: 18123)

    prepared = repro_regression.prepare(manifest)

    with connect(settings) as conn:
        task = repo.get_repro_task(conn, prepared["task_ids"][0])
    assert task and task["web_port"] == 18123
