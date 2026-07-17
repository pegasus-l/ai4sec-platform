from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ScoreResult(BaseModel):
    score: float
    priority: str = "medium"
    grade: str = "中"
    breakdown: dict[str, float] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    signals: dict[str, Any] = Field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return self.model_dump()
