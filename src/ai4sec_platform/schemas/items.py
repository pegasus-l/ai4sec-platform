from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class DomainItem(BaseModel):
    id: int | None = None
    domain: str
    item_type: str
    title: str
    summary: str = ""
    score: float | None = None
    status: str = "active"
    payload: dict[str, Any] = Field(default_factory=dict)
