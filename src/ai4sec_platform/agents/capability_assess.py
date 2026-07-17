from __future__ import annotations

from typing import Any

from ai4sec_platform.agents.base import Agent
from ai4sec_platform.models.local_rules import LocalRuleProvider


class CapabilityAssessAgent(Agent):
    name = "capability_assess"

    def run(self, input_data: Any) -> dict[str, Any]:
        return LocalRuleProvider().complete_json(prompt="能力评估", payload=self._as_dict(input_data))
