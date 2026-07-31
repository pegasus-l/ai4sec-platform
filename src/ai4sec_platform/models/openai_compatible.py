from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.request
from typing import Any


class OpenAICompatibleProvider:
    def __init__(self, *, base_url: str = "", api_key: str = "", model: str = "", provider_name: str = "openai_compatible", timeout_seconds: float = 45.0, max_output_tokens: int = 4096) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.provider_name = provider_name
        self.timeout_seconds = timeout_seconds
        self.max_output_tokens = max_output_tokens

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
            "max_tokens": self.max_output_tokens,
            "temperature": 0,
        }
        data = self._post(body)
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "{}")
        if not str(content).strip():
            retry_body = dict(body)
            retry_body.pop("response_format", None)
            retry_body["max_tokens"] = min(self.max_output_tokens * 2, 65536)
            data = self._post(retry_body)
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        content = str(content).strip()
        if not content:
            raise RuntimeError("model returned empty content")
        parsed = _parse_json_object(content)
        if not isinstance(parsed, dict):
            raise RuntimeError("model returned non-object JSON")
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

    def _post_once(self, body: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:  # noqa: S310 - configured internal/API endpoint
            deadline = time.monotonic() + self.timeout_seconds
            chunks: list[bytes] = []
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"model response exceeded {self.timeout_seconds:g}s total deadline")
                _set_response_socket_timeout(response, min(remaining, 15.0))
                try:
                    chunk = response.read(64 * 1024)
                except socket.timeout as exc:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"model response exceeded {self.timeout_seconds:g}s total deadline") from exc
                    continue
                if not chunk:
                    break
                chunks.append(chunk)
            return json.loads(b"".join(chunks).decode("utf-8"))


def _set_response_socket_timeout(response: Any, timeout_seconds: float) -> None:
    try:
        response.fp.raw._sock.settimeout(timeout_seconds)
    except AttributeError:
        return


def _parse_json_object(content: str) -> dict[str, Any]:
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    candidates: list[tuple[int, int, dict[str, Any]]] = []
    decoder = json.JSONDecoder()
    for block in re.findall(r"```(?:json)?\s*([\s\S]*?)```", content, flags=re.IGNORECASE):
        try:
            parsed = json.loads(block.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            candidates.append((len(block), len(content), parsed))
    for start, character in enumerate(content):
        if character != "{":
            continue
        try:
            parsed, consumed = decoder.raw_decode(content[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            candidates.append((consumed, start + consumed, parsed))
    if not candidates:
        raise RuntimeError("model returned invalid JSON")
    return max(candidates, key=lambda candidate: (candidate[0], candidate[1]))[2]
