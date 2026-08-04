from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities.repro_policy import enqueue_repro_task
from ai4sec_platform.domains.capabilities.repro_profiles import review_nested_docker_profile


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare and report isolated capability reproduction regressions")
    parser.add_argument("command", choices=("prepare", "report"))
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "prepare":
        payload = prepare(args.manifest)
    else:
        payload = report(args.manifest)
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))
    return 0


def prepare(manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    settings = load_settings()
    validate_regression_settings(settings)
    task_ids: list[int] = []
    with connect(settings) as conn:
        init_db(conn)
        for sample in manifest:
            item_id = repo.create_domain_item(
                conn,
                domain="capabilities",
                item_type="capability",
                title=f"Regression: {sample['sample_id']}",
                summary="Isolated multi-stack capability reproduction regression sample",
                source="capability_repro_regression",
                source_url=sample["repository_url"],
                payload={
                    "code_url": sample["repository_url"],
                    "implementation_depth": {"has_real_code": True},
                    "regression_sample_id": sample["sample_id"],
                    "regression_expected": sample.get("expected_capability", ""),
                },
            )
            task_id = enqueue_repro_task(
                conn,
                item_id=item_id,
                repo_url=sample["repository_url"],
                repo_commit=sample["commit_sha"],
                trigger="capability_repro_regression",
                initial_status="awaiting_profile_approval",
                execution_profile="nested_docker",
                repro_strategy=sample.get("strategy", "cli"),
            )
            review_nested_docker_profile(
                conn,
                task_id=task_id,
                decision="approved",
                reviewed_by="regression-operator",
                reason="Approved isolated regression sample; nested Docker is required by the current single-host runner.",
            )
            task_ids.append(task_id)
        conn.commit()
    return {"database": str(settings.database_path), "task_ids": task_ids, "sample_count": len(task_ids)}


def report(manifest_path: Path) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    expected = {sample["sample_id"]: sample for sample in manifest}
    settings = load_settings()
    validate_regression_settings(settings)
    with connect(settings) as conn:
        init_db(conn)
        rows = conn.execute(
            """
            WITH ranked_attempts AS (
                SELECT
                    t.*,
                    json_extract(i.payload_json, '$.regression_sample_id') AS sample_id,
                    COUNT(*) OVER (
                        PARTITION BY json_extract(i.payload_json, '$.regression_sample_id')
                    ) AS attempt_count,
                    ROW_NUMBER() OVER (
                        PARTITION BY json_extract(i.payload_json, '$.regression_sample_id')
                        ORDER BY t.id DESC
                    ) AS attempt_rank
                FROM capability_repro_tasks t
                JOIN domain_items i ON i.id = t.item_id
                WHERE json_extract(i.payload_json, '$.regression_sample_id') <> ''
            )
            SELECT * FROM ranked_attempts
            WHERE attempt_rank = 1
            ORDER BY id
            """
        ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        sample_id = str(item.get("sample_id") or "")
        items.append({
            "sample_id": sample_id,
            "task_id": item["id"],
            "attempt_count": item["attempt_count"],
            "repo_commit": item.get("repo_commit", ""),
            "status": item["status"],
            "result": item.get("result", "")[-1000:],
            "expected_capability": expected.get(sample_id, {}).get("expected_capability", ""),
        })
    counts: dict[str, int] = {}
    for item in items:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    return {"database": str(settings.database_path), "sample_count": len(expected), "counts": counts, "items": items}


def load_manifest(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    samples = payload.get("samples") if isinstance(payload, dict) else None
    if not isinstance(samples, list) or not 1 <= len(samples) <= 20:
        raise ValueError("regression manifest must contain 1-20 samples")
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for sample in samples:
        if not isinstance(sample, dict):
            raise ValueError("each regression sample must be an object")
        sample_id = str(sample.get("sample_id") or "")
        repository_url = str(sample.get("repository_url") or "")
        commit_sha = str(sample.get("commit_sha") or "").casefold()
        if not sample_id or sample_id in seen:
            raise ValueError("sample IDs must be non-empty and unique")
        if not repository_url.startswith("https://github.com/"):
            raise ValueError(f"sample {sample_id} must use a public GitHub URL")
        if len(commit_sha) != 40 or any(character not in "0123456789abcdef" for character in commit_sha):
            raise ValueError(f"sample {sample_id} must pin a 40-character commit SHA")
        seen.add(sample_id)
        normalized.append({**sample, "sample_id": sample_id, "repository_url": repository_url, "commit_sha": commit_sha})
    return normalized


def validate_regression_settings(settings) -> None:
    if os.environ.get("AI4SEC_REPRO_REGRESSION_CONFIRM") != "isolated-regression":
        raise RuntimeError("set AI4SEC_REPRO_REGRESSION_CONFIRM=isolated-regression before using the regression CLI")
    database_path = settings.database_path.expanduser().resolve()
    output_path = settings.output_dir.expanduser().resolve()
    if "repro-regression" not in database_path.parts or "repro-regression" not in output_path.parts:
        raise RuntimeError("regression database and output paths must be inside a repro-regression directory")
    if database_path == (settings.project_root / "output" / "ai4sec_platform.db").resolve():
        raise RuntimeError("regression CLI refuses to use the platform database")


if __name__ == "__main__":
    raise SystemExit(main())
