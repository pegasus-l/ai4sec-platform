from __future__ import annotations

import os

from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.openai_compatible import OpenAICompatibleProvider


class LLMRouter:
    def __init__(self) -> None:
        self._local_rules = LocalRuleProvider()

    def provider_for(self, profile: str = "local_rules"):
        provider = os.getenv("AI4SEC_MODEL_PROVIDER", profile)
        if provider in {"local_rules", "rule_based", "offline"}:
            return self._local_rules
        return OpenAICompatibleProvider(
            base_url=os.getenv("AI4SEC_OPENAI_BASE_URL", ""),
            api_key=os.getenv("AI4SEC_OPENAI_API_KEY", ""),
            model=os.getenv("AI4SEC_OPENAI_MODEL", ""),
        )

    def complete_json(self, *, profile: str = "local_rules", prompt: str, payload: dict) -> dict:
        return self.provider_for(profile).complete_json(prompt=prompt, payload=payload)
