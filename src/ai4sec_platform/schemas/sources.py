from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class SourceFetchRequest(BaseModel):
    source_name: str
    config: dict[str, Any] = Field(default_factory=dict)
    params: dict[str, Any] = Field(default_factory=dict)


class SourceHealth(BaseModel):
    status: str = "unknown"
    message: str = ""
