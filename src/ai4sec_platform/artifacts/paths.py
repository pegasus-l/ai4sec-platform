from __future__ import annotations

from pathlib import Path


def shadow_run_dir(output_dir: Path, run_id: str) -> Path:
    return output_dir / "shadow_runs" / run_id
