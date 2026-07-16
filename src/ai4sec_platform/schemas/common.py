from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class APIResponse(BaseModel):
    status: str = "ok"
    data: Any = None


class Page(BaseModel):
    items: list[Any] = Field(default_factory=list)
    count: int = 0
