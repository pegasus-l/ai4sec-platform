from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class PipelineRunRequest(BaseModel):
    pipeline_name: str
    reset: bool = False
    params: dict[str, Any] = Field(default_factory=dict)


class PipelineRunSummary(BaseModel):
    run_id: str
    pipeline_name: str
    domain: str
    status: str
