from __future__ import annotations

import json
import urllib.request
from typing import Any


class OpenAICompatibleProvider:
    def __init__(self, *, base_url: str = "", api_key: str = "", model: str = "") -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model

    def complete_json(self, *, prompt: str, payload: dict) -> dict[str, Any]:
        if not self.base_url or not self.api_key or not self.model:
            raise RuntimeError("OpenAI-compatible provider requires base_url, api_key and model")
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ],
            "response_format": {"type": "json_object"},
        }
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - configured internal/API endpoint
            data = json.loads(response.read().decode("utf-8"))
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = {"raw_content": content}
        return {"provider_response": data, "parsed": parsed}
