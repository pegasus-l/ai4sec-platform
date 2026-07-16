from __future__ import annotations


class OpenAICompatibleProvider:
    def __init__(self, *, base_url: str = "", api_key: str = "", model: str = "") -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.model = model

    def complete_json(self, *, prompt: str, payload: dict) -> dict:
        raise NotImplementedError("OpenAI-compatible provider is not enabled in the shadow skeleton yet.")
