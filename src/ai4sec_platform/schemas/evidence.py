from __future__ import annotations

from pydantic import BaseModel


class Evidence(BaseModel):
    domain: str
    title: str
    content: str = ""
    confidence: float | None = None
