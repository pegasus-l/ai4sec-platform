from __future__ import annotations


class MockProvider:
    def complete_json(self, *, prompt: str, payload: dict) -> dict:
        return {"status": "mock", "prompt": prompt[:120], "payload": payload}
