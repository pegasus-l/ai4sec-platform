from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


NewsItemType = Literal["paper", "project", "article", "tool", "report"]
ReadingState = Literal["unread", "read", "bookmarked", "later", "ignored"]


class NormalizedNewsItem(BaseModel):
    item_key: str
    source: str
    source_type: NewsItemType
    title: str
    url: str = ""
    primary_date: str = ""
    updated_at: str = ""
    summary: str = ""
    authors: list[str] = Field(default_factory=list)
    topics: list[str] = Field(default_factory=list)
    code_url: str = ""
    paper_url: str = ""
    external_id: str = ""
    repo_full_name: str = ""
    stars: int = 0
    forks: int = 0
    language: str = ""
    discovered_from: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class NewsActionRequest(BaseModel):
    operator: str = "operator"
    reason: str = ""
    value: str = ""


class NewsListQuery(BaseModel):
    query: str = ""
    item_type: str = ""
    source: str = ""
    topic: str = ""
    status: str = ""
    date_from: str = ""
    date_to: str = ""
    min_score: float | None = None
    sort: str = "score"
    page: int = 1
    page_size: int = 30
    operator: str = "operator"
