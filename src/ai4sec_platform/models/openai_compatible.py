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
        self.timeout_seconds = max(float(timeout_seconds), 5.0)
        self.max_output_tokens = max_output_tokens
        # 兜底: 任何漏配 timeout 的 socket 继承进程级默认, 避免 read 无限阻塞。
        # 已显式设过默认值(其它模块)则不覆盖。
        if socket.getdefaulttimeout() is None:
            socket.setdefaulttimeout(self.timeout_seconds)

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
        content = _message_content(data, default="{}")
        if not str(content).strip():
            retry_body = dict(body)
            retry_body.pop("response_format", None)
            retry_body["max_tokens"] = min(self.max_output_tokens * 2, 65536)
            data = self._post(retry_body)
            content = _message_content(data)
        content = str(content).strip()
        if not content:
            raise RuntimeError("model returned empty content")
        parsed = _parse_json_object(content)
        if parsed is None or not isinstance(parsed, dict):
            # 模型偶发给出非法 JSON(截断 / 尾逗号 / 裸换行)。再要一次, 并明确只回 JSON。
            # 不做这层兜底的话调用方直接抛错, 一条坏输出会带崩整条 pipeline —— 09-15 的
            # threats.huawei_full_migration_pipeline 就是这样: 前 8 步全 success,
            # 只有 reason_threat_risk 报 "model returned invalid JSON" 整条判 failed。
            repair_body = dict(body)
            repair_body["max_tokens"] = min(self.max_output_tokens * 2, 65536)
            repair_body["messages"] = [
                {"role": "system", "content": f"{prompt}\n\n上一次输出不是合法 JSON。只输出一个 JSON 对象, 不要 markdown 代码块, 不要任何解释文字。"},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
            ]
            parsed = _parse_json_object(_message_content(self._post(repair_body)))
        if parsed is None:
            raise RuntimeError("model returned invalid JSON")
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
                    # read1 至多取一次底层 raw read 的结果, 立即返回 → 每轮都过 deadline 检查。
                    # 不能再用 read(64*1024): BufferedReader.read(amt) 会内部循环读到 amt/EOF,
                    # 服务端慢速 dribble(每 <15s 来一点字节)时 socket.timeout 永不触发, deadline 形同虚设。
                    chunk = response.read1(8 * 1024)
                except (socket.timeout, TimeoutError) as exc:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"model response exceeded {self.timeout_seconds:g}s total deadline") from exc
                    continue
                if not chunk:
                    break
                chunks.append(chunk)
            return json.loads(b"".join(chunks).decode("utf-8"))


def _message_content(data: dict[str, Any], default: str = "") -> str:
    """从 chat/completions 响应里取 message.content。"""
    return data.get("choices", [{}])[0].get("message", {}).get("content", default)


def _parse_json_object(content: Any) -> Any:
    """把模型输出解析成 JSON; 解不出来返回 None(由调用方决定重试还是报错)。

    比裸 json.loads 多三层容忍, 都是线上真见过的形态:
      1. markdown 代码块包裹;
      2. 前后带解释文字 → 截取首个 { 到末个 };
      3. 对象/数组尾部的多余逗号。
    返回非 dict 的合法 JSON(如数组)也照原样返回, 由调用方判 "non-object"。
    """
    text = str(content or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    if not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start:end + 1]
    for candidate in (text, re.sub(r",(\s*[}\]])", r"\1", text)):
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            continue
    return None


def _set_response_socket_timeout(response: Any, timeout_seconds: float) -> None:
    """多路径取响应底层 socket 并设 read 超时; 全部失败时用进程级 setdefaulttimeout 兜底。

    不再静默吞 AttributeError —— 那是 16h 卡死的帮凶之一: 路径取不到时 socket 保持无/大超时,
    read 可能无限阻塞。这里保证任意路径下 read 都有界。
    """
    sock = None
    fp = getattr(response, "fp", None)
    raw = getattr(fp, "raw", None)
    if raw is not None:
        sock = getattr(raw, "_sock", None)
    if sock is None and fp is not None:
        sock = getattr(fp, "_sock", None)
    if sock is None:
        sock = getattr(response, "_sock", None)
    if sock is not None and hasattr(sock, "settimeout"):
        sock.settimeout(max(float(timeout_seconds), 0.1))
        return
    socket.setdefaulttimeout(max(float(timeout_seconds), 0.1))
