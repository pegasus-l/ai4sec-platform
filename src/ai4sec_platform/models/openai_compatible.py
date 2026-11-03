from __future__ import annotations

import json
import re
import socket
import time
import urllib.error
import urllib.request
from typing import Any, Mapping

# litellm 网关在响应头里交代"这一回到底是谁答的"。这是**唯一**能拿到真实上游的地方:
# 响应体的 `model` 字段只回组别名(实测 `chat-primary`), 组里挂着 6 把 key + 1 个备用厂商,
# 从现在的位置看不出差别。评测结论与"这份分数是哪家模型跑的"直接相关, 所以这几个头要抬上来。
_SERVING_HEADERS = (
    ("upstream_model", "x-litellm-model-name"),
    ("upstream_group", "x-litellm-model-group"),
    ("upstream_api_base", "x-litellm-model-api-base"),
    ("gateway_call_id", "x-litellm-call-id"),
)
_USAGE_FIELDS = ("prompt_tokens", "completion_tokens", "total_tokens")


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
        data, headers = self._post(body)
        content = _message_content(data, default="{}")
        if not str(content).strip():
            retry_body = dict(body)
            retry_body.pop("response_format", None)
            retry_body["max_tokens"] = min(self.max_output_tokens * 2, 65536)
            data, headers = self._post(retry_body)
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
            data, headers = self._post(repair_body)
            parsed = _parse_json_object(_message_content(data))
        if parsed is None:
            raise RuntimeError("model returned invalid JSON")
        if not isinstance(parsed, dict):
            raise RuntimeError("model returned non-object JSON")
        return {"provider": self.provider_name, "status": "success", "model": self.model,
                "parsed": parsed, "result": parsed,
                # `model` 是"我请求的谁", `serving` 是"实际谁答的"。两者在网关降级/中转时会分叉,
                # 评测报告要的是后者。
                "serving": _serving_from_headers(headers, requested_model=self.model),
                "usage": _usage_from_body(data)}

    def chat_completion(self, *, messages: list[dict[str, Any]],
                        max_tokens: int | None = None,
                        temperature: float | None = None,
                        tools: list[dict[str, Any]] | None = None,
                        tool_choice: Any = None,
                        response_format: dict[str, Any] | None = None) -> dict[str, Any]:
        """原样的 Chat Completions 调用: 不解析 JSON, 不重试改写提示词。

        与 `complete_json` 是**两条用途**不同的路:
          · `complete_json` 是平台自己要"一个 JSON 结论", 解析失败会重试/修复;
          · 这里是把第三方工具原封不动的请求转过去, 它的输出就是它的输出 ——
            我们替它重写提示词, 测的就不是那个工具了。

        `tools` / `tool_choice` / `response_format` **原样透传且不降级**: 被测工具靠它们
        拿结构化结果(`with_structured_output` 默认就是 function calling)。网关若不认,
        错误原样抛回去 —— 悄悄删掉 `response_format` 再试(`_post` 的做法)会让工具拿到
        一段散文当成结论, 那种"跑通了但是错的"比失败难查得多。

        返回里的 `serving` 仍然取自网关响应头: 报告要能回答"这一轮实际是谁答的"。
        """
        if not self.base_url or not self.api_key or not self.model:
            raise RuntimeError("OpenAI-compatible provider requires base_url, api_key and model")
        body: dict[str, Any] = {"model": self.model, "messages": messages}
        if max_tokens:
            body["max_tokens"] = int(max_tokens)
        if temperature is not None:
            body["temperature"] = float(temperature)
        if tools:
            body["tools"] = tools
        if tool_choice is not None:
            body["tool_choice"] = tool_choice
        if response_format:
            body["response_format"] = response_format
        data, headers = self._post_once(body)
        choices = (data.get("choices") if isinstance(data, dict) else None) or []
        choice = choices[0] if choices and isinstance(choices[0], dict) else {}
        return {"provider": self.provider_name,
                "content": _message_content(data, default=""),
                "tool_calls": _message_tool_calls(data),
                "finish_reason": choice.get("finish_reason") or "",
                "serving": _serving_from_headers(headers, requested_model=self.model),
                "usage": _usage_from_body(data)}

    def _post(self, body: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, str]]:
        try:
            return self._post_once(body)
        except urllib.error.HTTPError as exc:
            if exc.code not in {400, 422} or "response_format" not in body:
                raise
            retry_body = dict(body)
            retry_body.pop("response_format", None)
            return self._post_once(retry_body)

    def _post_once(self, body: dict[str, Any]) -> tuple[dict[str, Any], Mapping[str, str]]:
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
            return json.loads(b"".join(chunks).decode("utf-8")), dict(response.headers.items())


def _serving_from_headers(headers: Mapping[str, str] | None, *,
                          requested_model: str) -> dict[str, Any]:
    """把"这一回实际是谁答的"整理成可落库的字段。

    三个诚实性规则, 都是为了让报告能回答"这份分数是哪家模型跑的":

    1. **读不到头就落 `unknown`**, 绝不回填成配置里的模型名。配置说的是"我请求了谁",
       不是"谁答的"; 降级、中转、网关重写都会让两者分叉, 而评测结论正依赖这个区别。
    2. **降级/重试次数没读到就是 `None`, 不是 0**。"0 次降级"是一条结论, "不知道"是另一条。
    3. `source` 标明这组字段的可信度: `gateway_header` 才是网关亲口说的; `unverified`
       表示这次调用没有经过会带头的网关(比如直连上游)。
    """
    lowered = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    serving: dict[str, Any] = {
        "requested_model": requested_model,
        "upstream_model": "unknown",
        "source": "unverified",
    }
    for field, header in _SERVING_HEADERS:
        value = lowered.get(header, "")
        if value:
            serving[field] = value
    # 只有网关亲口报了模型, 才敢说这次可核验
    if serving.get("upstream_model") != "unknown":
        serving["source"] = "gateway_header"
    for field, header in (("attempted_fallbacks", "x-litellm-attempted-fallbacks"),
                          ("attempted_retries", "x-litellm-attempted-retries")):
        raw = lowered.get(header, "")
        serving[field] = int(raw) if raw.isdigit() else None
    return serving


def _usage_from_body(data: Any) -> dict[str, int]:
    """token 用量。模型不在网关价目表里 ⇒ 计费恒为 0(只能报 token, 不能报金额)。"""
    usage = data.get("usage") if isinstance(data, dict) else None
    if not isinstance(usage, dict):
        return {}
    return {key: usage[key] for key in _USAGE_FIELDS if isinstance(usage.get(key), int)}


def _message_content(data: dict[str, Any], default: str = "") -> str:
    """从 chat/completions 响应里取 message.content。"""
    return data.get("choices", [{}])[0].get("message", {}).get("content", default)


def _message_tool_calls(data: dict[str, Any]) -> list[dict[str, Any]]:
    """从 chat/completions 响应里取 message.tool_calls。

    function calling 的回复里 `content` 常常是 None, 结论全在 `tool_calls` 里。
    这里只做形状过滤(丢掉不是对象的项), 不解析 `arguments` —— 那是调用方的事,
    我们这一层不加任何解释。
    """
    raw = data.get("choices", [{}])[0].get("message", {}).get("tool_calls")
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


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
