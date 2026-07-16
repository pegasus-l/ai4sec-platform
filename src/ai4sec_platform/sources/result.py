from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class SourceFetchResult(BaseModel):
    source_name: str
    connector_name: str
    items: list[dict[str, Any]] = Field(default_factory=list)
    raw_text: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    errors: list[str] = Field(default_factory=list)
