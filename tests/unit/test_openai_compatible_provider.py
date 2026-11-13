import pytest

from ai4sec_platform.models.openai_compatible import (
    OpenAICompatibleProvider,
    _serving_from_headers,
)
from ai4sec_platform.models.router import FallbackProvider


def test_provider_retries_empty_json_mode_response(monkeypatch) -> None:
    provider = OpenAICompatibleProvider(base_url="https://example.test/v1", api_key="key", model="model")
    responses = iter(
        [
            ({"choices": [{"message": {"content": ""}}]}, {}),
            ({"choices": [{"message": {"content": '{"ok": true}'}}]}, {}),
        ]
    )
    seen_bodies = []
    monkeypatch.setattr(provider, "_post", lambda body: seen_bodies.append(body) or next(responses))

    response = provider.complete_json(prompt="return JSON", payload={})

    assert response["result"] == {"ok": True}
    assert "response_format" not in seen_bodies[1]
    assert seen_bodies[1]["max_tokens"] == 8192


def test_provider_rejects_invalid_json(monkeypatch) -> None:
    provider = OpenAICompatibleProvider(base_url="https://example.test/v1", api_key="key", model="model")
    monkeypatch.setattr(
        provider, "_post",
        lambda body: ({"choices": [{"message": {"content": "not json"}}]}, {}))

    with pytest.raises(RuntimeError, match="invalid JSON"):
        provider.complete_json(prompt="return JSON", payload={})


def test_serving_reads_the_gateway_headers() -> None:
    """这几行头是**唯一**能说清"实际谁答的"的地方 —— 响应体的 model 只回组别名。"""
    serving = _serving_from_headers({
        "X-LiteLLM-Model-Name": "openai/deepseek-v4-flash",
        "X-LiteLLM-Model-Group": "chat-primary",
        "X-LiteLLM-Model-Api-Base": "https://volc.example/v1",
        "X-LiteLLM-Call-Id": "abc",
        "X-LiteLLM-Attempted-Fallbacks": "1",
        "X-LiteLLM-Attempted-Retries": "0",
    }, requested_model="chat-primary")

    assert serving["upstream_model"] == "openai/deepseek-v4-flash"
    assert serving["upstream_group"] == "chat-primary"
    assert serving["upstream_api_base"] == "https://volc.example/v1"
    assert serving["source"] == "gateway_header"
    assert serving["attempted_fallbacks"] == 1


def test_serving_without_gateway_headers_stays_unknown() -> None:
    """读不到头就是 `unknown`, **绝不**回填配置里的模型名。

    配置说的是"我请求了谁", 不是"谁答的"; 降级/中转/直连都会让两者分叉,
    而评测结论正依赖这个区别。
    """
    serving = _serving_from_headers({"Date": "now"}, requested_model="chat-primary")

    assert serving["upstream_model"] == "unknown"
    assert serving["source"] == "unverified"
    assert serving["requested_model"] == "chat-primary"
    # "没读到"和"0 次降级"是两个结论, 不能都写成 0
    assert serving["attempted_fallbacks"] is None


def test_complete_json_carries_serving_and_usage(monkeypatch) -> None:
    provider = OpenAICompatibleProvider(base_url="https://gw.test/v1", api_key="key", model="chat-primary")
    body = {
        "choices": [{"message": {"content": '{"ok": true}'}}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
    }
    monkeypatch.setattr(
        provider, "_post",
        lambda _b: (body, {"x-litellm-model-name": "openai/deepseek-v4-flash"}))

    response = provider.complete_json(prompt="return JSON", payload={})

    assert response["model"] == "chat-primary"            # 请求的别名
    assert response["serving"]["upstream_model"] == "openai/deepseek-v4-flash"  # 实际服务的模型
    assert response["usage"] == {"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18}


def test_fallback_provider_keeps_the_serving_of_whichever_answered() -> None:
    class FakeProvider:
        provider_name = "backup"

        def complete_json(self, *, prompt, payload):
            return {"status": "success", "result": {},
                    "serving": {"upstream_model": "vendor/model"}}

    result = FallbackProvider([FakeProvider()]).complete_json(prompt="p", payload={})

    assert result["provider"] == "backup"
    assert result["serving"]["upstream_model"] == "vendor/model"


# ── 原样转发(function calling)────────────────────────────────────────────────

TOOLS = [{"type": "function",
          "function": {"name": "report_finding", "parameters": {"type": "object"}}}]


def test_chat_completion_forwards_tool_arguments_verbatim(monkeypatch) -> None:
    """`tools` / `tool_choice` / `response_format` 必须原样进请求体。

    被测工具靠这三个拿结构化答案。少传一个, 它就会退化成"让模型输出 JSON 再正则" ——
    那测的已经不是那个工具了。
    """
    provider = OpenAICompatibleProvider(base_url="https://gw.test/v1", api_key="key", model="chat-primary")
    seen: list[dict] = []

    def _fake_post(body):
        seen.append(body)
        return ({"choices": [{"message": {"content": None, "tool_calls": [
                    {"id": "call_1", "type": "function",
                     "function": {"name": "report_finding", "arguments": "{\"line\": 42}"}}]},
                 "finish_reason": "tool_calls"}],
                 "usage": {"prompt_tokens": 3, "completion_tokens": 1}}, {})

    monkeypatch.setattr(provider, "_post_once", _fake_post)

    result = provider.chat_completion(
        messages=[{"role": "user", "content": "audit"}],
        tools=TOOLS, tool_choice="auto", response_format={"type": "json_object"})

    assert seen[0]["tools"] == TOOLS
    assert seen[0]["tool_choice"] == "auto"
    assert seen[0]["response_format"] == {"type": "json_object"}
    assert result["content"] is None
    assert result["tool_calls"][0]["function"]["arguments"] == "{\"line\": 42}"
    assert result["finish_reason"] == "tool_calls"


def test_chat_completion_does_not_quietly_drop_response_format(monkeypatch) -> None:
    """`complete_json` 在 400 时会删掉 response_format 重试, 这里**不能**这么做。

    悄悄去掉之后模型照常回一段散文, 工具会把它当成结论 —— 那种"跑通了但是错的"
    比一次明确的失败难查得多。
    """
    import urllib.error

    provider = OpenAICompatibleProvider(base_url="https://gw.test/v1", api_key="key", model="chat-primary")
    seen: list[dict] = []

    def _fake_post(body):
        seen.append(body)
        raise urllib.error.HTTPError("https://gw.test/v1/chat/completions", 400, "Bad Request", {}, None)

    monkeypatch.setattr(provider, "_post_once", _fake_post)

    with pytest.raises(urllib.error.HTTPError):
        provider.chat_completion(messages=[{"role": "user", "content": "x"}],
                                 response_format={"type": "json_object"})

    # 只打了一次: 没有"删掉 response_format 再试一遍"的第二次
    assert len(seen) == 1


def test_fallback_provider_carries_tool_arguments_to_the_next_provider() -> None:
    """降级到第二家时也得带着 tools, 否则工具会突然收到一段散文。"""
    received: dict = {}

    class FakeProvider:
        provider_name = "backup"

        def chat_completion(self, **kwargs):
            received.update(kwargs)
            return {"provider": "backup", "content": "", "tool_calls": [], "serving": {}}

    FallbackProvider([FakeProvider()]).chat_completion(
        messages=[{"role": "user", "content": "x"}],
        tools=TOOLS, tool_choice="required", response_format={"type": "json_object"})

    assert received["tools"] == TOOLS
    assert received["tool_choice"] == "required"
    assert received["response_format"] == {"type": "json_object"}
