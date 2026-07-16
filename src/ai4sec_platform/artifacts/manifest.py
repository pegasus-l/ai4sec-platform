from __future__ import annotations

from typing import Any

from ai4sec_platform.artifacts.store import ArtifactStore


def write_manifest(conn, store: ArtifactStore, *, run_id: str, summary: dict[str, Any], artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    manifest = {
        "run_id": run_id,
        "production_writes": False,
        "summary": summary,
        "artifacts": artifacts,
    }
    store.write_json(conn, run_id=run_id, artifact_type="manifest", name="manifest.json", data=manifest)
    return manifest
