from __future__ import annotations

from pydantic import BaseModel


class ArtifactRef(BaseModel):
    path: str
    sha256: str = ""
    bytes: int = 0
    artifact_type: str = ""
