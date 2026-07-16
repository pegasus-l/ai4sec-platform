from __future__ import annotations

from pydantic import BaseModel


class ThreatTarget(BaseModel):
    title: str
    risk_score: float | None = None
    status: str = "待研判"
