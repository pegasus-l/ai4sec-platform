from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai4sec_platform.cli import repro_regression
from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
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
