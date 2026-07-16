from __future__ import annotations

from typing import Protocol


class LLMProvider(Protocol):
    def complete_json(self, *, prompt: str, payload: dict) -> dict:
        ...
