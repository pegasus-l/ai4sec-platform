from __future__ import annotations

from pydantic import BaseModel


class HumanQueueItem(BaseModel):
    domain: str
    queue_type: str
    status: str = "pending"
    priority: int = 3
    reason: str = ""
