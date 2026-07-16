from __future__ import annotations

from typing import Any

from ai4sec_platform.agents.base import Agent


class RiskReasoningAgent(Agent):
    name = "risk_reasoning"

    def run(self, input_data: Any) -> dict[str, Any]:
        return {"agent": self.name, "status": "planned", "input_preview": str(input_data)[:200]}
