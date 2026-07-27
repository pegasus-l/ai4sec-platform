from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Any


@dataclass(frozen=True)
class SearchTimeRange:
    mode: str
    start_date: str
    end_date: str
    label: str


def resolve_search_time_range(params: dict[str, Any], *, today: date | None = None) -> SearchTimeRange:
    current = today or date.today()
    mode = str(params.get("time_range_mode") or "recent_days").strip()
    if mode == "none":
        return SearchTimeRange(mode=mode, start_date="", end_date="", label="不限时间")
    if mode == "current_month":
        start = current.replace(day=1)
        return SearchTimeRange(mode=mode, start_date=start.isoformat(), end_date=current.isoformat(), label=f"本月 {start.isoformat()} 至 {current.isoformat()}")
    if mode == "custom":
        start = _parse_date(params.get("start_date"), "start_date")
        end = _parse_date(params.get("end_date"), "end_date")
        if start > end:
            raise ValueError("start_date must not be after end_date")
        return SearchTimeRange(mode=mode, start_date=start.isoformat(), end_date=end.isoformat(), label=f"{start.isoformat()} 至 {end.isoformat()}")
    if mode != "recent_days":
        raise ValueError(f"unsupported time_range_mode: {mode}")
    days = _positive_int(params.get("recent_days"), 30)
    start = current - timedelta(days=days - 1)
    return SearchTimeRange(mode=mode, start_date=start.isoformat(), end_date=current.isoformat(), label=f"最近 {days} 天")


def apply_search_time_range(queries: list[str], time_range: SearchTimeRange) -> list[str]:
    if not time_range.start_date:
        return list(queries)
    return [f"查找安全研究员在{time_range.start_date}至{time_range.end_date}公开发表的关于{query}漏洞最新文件" for query in queries]


def _parse_date(value: Any, field_name: str) -> date:
    try:
        return date.fromisoformat(str(value or ""))
    except ValueError as exc:
        raise ValueError(f"{field_name} must use YYYY-MM-DD") from exc


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default
