from __future__ import annotations

import os

from ai4sec_platform.models.mock import MockProvider
from ai4sec_platform.models.openai_compatible import OpenAICompatibleProvider


class LLMRouter:
    def __init__(self) -> None:
        self._mock = MockProvider()

    def provider_for(self, profile: str = "mock_default"):
        if profile == "mock_default" or os.getenv("AI4SEC_FORCE_MOCK_MODEL", "1") != "0":
            return self._mock
        return OpenAICompatibleProvider(
            base_url=os.getenv("AI4SEC_OPENAI_BASE_URL", ""),
            api_key=os.getenv("AI4SEC_OPENAI_API_KEY", ""),
            model=os.getenv("AI4SEC_OPENAI_MODEL", ""),
        )

    def complete_json(self, *, profile: str = "mock_default", prompt: str, payload: dict) -> dict:
        return self.provider_for(profile).complete_json(prompt=prompt, payload=payload)
