from __future__ import annotations

from ai4sec_platform.models.mock import MockProvider


class LLMRouter:
    def __init__(self) -> None:
        self._mock = MockProvider()

    def provider_for(self, profile: str = "mock_default"):
        return self._mock

    def complete_json(self, *, profile: str = "mock_default", prompt: str, payload: dict) -> dict:
        return self.provider_for(profile).complete_json(prompt=prompt, payload=payload)
