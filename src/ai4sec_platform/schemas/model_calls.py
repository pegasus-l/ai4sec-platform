from __future__ import annotations

from pydantic import BaseModel


class ModelCall(BaseModel):
    agent_name: str
    model_profile: str
    status: str = "pending"
