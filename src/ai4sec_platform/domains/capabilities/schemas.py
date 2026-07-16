from __future__ import annotations

from pydantic import BaseModel


class CapabilityCandidate(BaseModel):
    title: str
    source_url: str = ""
    status: str = "待能力评估"
