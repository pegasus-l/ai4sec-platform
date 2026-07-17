from __future__ import annotations

from typing import Any

from ai4sec_platform.agents.base import Agent


class ReportSummaryAgent(Agent):
    name = "report_summary"

    def run(self, input_data: Any) -> dict[str, Any]:
        payload = self._as_dict(input_data)
        title = payload.get("title") or payload.get("name") or "未命名报告"
        summary = payload.get("summary") or payload.get("content") or payload.get("description") or ""
        return {"agent": self.name, "status": "success", "title": title, "summary": str(summary)[:800], "key_points": _key_points(payload)}


def _key_points(payload: dict[str, Any]) -> list[str]:
    points = payload.get("key_findings") or payload.get("findings") or []
    if isinstance(points, list):
        return [str(item) for item in points[:8]]
    return [str(points)] if points else []
