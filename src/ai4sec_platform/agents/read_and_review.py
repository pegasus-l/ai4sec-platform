from __future__ import annotations

from typing import Any

from ai4sec_platform.agents.base import Agent


class ReadAndReviewAgent(Agent):
    name = "read_and_review"

    def run(self, input_data: Any) -> dict[str, Any]:
        payload = self._as_dict(input_data)
        text = " ".join(str(payload.get(key, "")) for key in ["title", "summary", "content"])
        return {"agent": self.name, "status": "success", "summary": text[:500], "length": len(text), "has_source": bool(payload.get("source_url") or payload.get("url"))}
