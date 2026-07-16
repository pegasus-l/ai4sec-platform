from __future__ import annotations

from pydantic import BaseModel


class QualityAudit(BaseModel):
    domain: str
    audit_type: str
    status: str
    summary: str = ""
