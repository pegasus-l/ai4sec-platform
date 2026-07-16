from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ai4sec_platform.artifacts.checksum import sha256_file
from ai4sec_platform.db import repositories as repo


class ArtifactStore:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir

    def run_dir(self, run_id: str) -> Path:
        path = self.output_dir / "shadow_runs" / run_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def write_json(self, conn, *, run_id: str, artifact_type: str, name: str, data: Any) -> dict[str, Any]:
        path = self.run_dir(run_id) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        stat = path.stat()
        digest = sha256_file(path)
        repo.create_artifact(
            conn,
            run_id=run_id,
            artifact_type=artifact_type,
            path=str(path),
            sha256=digest,
            bytes_size=stat.st_size,
            payload_summary={"name": name, "type": artifact_type},
        )
        return {"path": str(path), "sha256": digest, "bytes": stat.st_size, "artifact_type": artifact_type}
