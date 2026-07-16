from __future__ import annotations

from ai4sec_platform.pipelines.runner import PipelineRunner


def run_pipeline(pipeline_name: str, params: dict | None = None) -> dict:
    return PipelineRunner().run(pipeline_name, params or {})
