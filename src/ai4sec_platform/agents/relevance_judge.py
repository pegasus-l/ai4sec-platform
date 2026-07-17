from __future__ import annotations

from typing import Any

from ai4sec_platform.agents.base import Agent


class RelevanceJudgeAgent(Agent):
    name = "relevance_judge"

    def run(self, input_data: Any) -> dict[str, Any]:
        payload = self._as_dict(input_data)
        text = " ".join(str(value) for value in payload.values()).lower()
        keywords = ["漏洞", "cve", "exploit", "poc", "attack", "llm", "agent", "security", "安全"]
        hits = [keyword for keyword in keywords if keyword in text]
        return {"agent": self.name, "status": "success", "is_relevant": bool(hits), "confidence": min(0.95, 0.4 + 0.1 * len(hits)), "matched_keywords": hits}
