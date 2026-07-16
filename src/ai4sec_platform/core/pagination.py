from __future__ import annotations

from pydantic import BaseModel, Field


class PageParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


def page_response(items: list, *, limit: int, offset: int, total: int | None = None) -> dict:
    return {"items": items, "limit": limit, "offset": offset, "count": len(items), "total": total}
