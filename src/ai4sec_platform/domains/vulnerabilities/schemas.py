from __future__ import annotations

from pydantic import BaseModel


class VulnerabilityMaterial(BaseModel):
    title: str
    source_url: str = ""
    status: str = "待知识提取"
