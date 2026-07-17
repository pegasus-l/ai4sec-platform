from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ClassificationResult(BaseModel):
    category: str
    subcategory: str = ""
    tags: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    reasons: list[str] = Field(default_factory=list)
    signals: dict[str, Any] = Field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return self.model_dump()
