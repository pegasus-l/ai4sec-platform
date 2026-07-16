from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class Entity(BaseModel):
    entity_key: str
    entity_type: str
    name: str
    payload: dict[str, Any] = Field(default_factory=dict)
