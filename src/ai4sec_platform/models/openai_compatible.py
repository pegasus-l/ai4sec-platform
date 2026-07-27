from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class OpenAICompatibleProvider:
    def __init__(self, *, base_url: str = "", api_key: str = "", model: str = "", provider_name: str = "openai_compatible") -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.provider_name = provider_name

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
            "temperature": 0,
        }
        data = self._post(body)
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            parsed = {"raw_content": content}
        return {"provider": self.provider_name, "status": "success", "model": self.model, "parsed": parsed, "result": parsed}

    def _post(self, body: dict[str, Any]) -> dict[str, Any]:
        try:
            return self._post_once(body)
        except urllib.error.HTTPError as exc:
            if exc.code not in {400, 422} or "response_format" not in body:
                raise
            retry_body = dict(body)
            retry_body.pop("response_format", None)
            return self._post_once(retry_body)
        except (urllib.error.URLError, TimeoutError, OSError):
            # 超时后重试 1 次（等待 2 秒再重试）
            import time
            time.sleep(2)
            return self._post_once(body)

    def _post_once(self, body: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - configured internal/API endpoint
            return json.loads(response.read().decode("utf-8"))
