import pytest

from ai4sec_platform.models.openai_compatible import OpenAICompatibleProvider


def test_provider_retries_empty_json_mode_response(monkeypatch) -> None:
    provider = OpenAICompatibleProvider(base_url="https://example.test/v1", api_key="key", model="model")
    responses = iter(
        [
            {"choices": [{"message": {"content": ""}}]},
            {"choices": [{"message": {"content": '{"ok": true}'}}]},
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
    monkeypatch.setattr(provider, "_post", lambda body: {"choices": [{"message": {"content": "not json"}}]})

    with pytest.raises(RuntimeError, match="invalid JSON"):
        provider.complete_json(prompt="return JSON", payload={})


def test_provider_extracts_json_object_from_reasoning_wrapper(monkeypatch) -> None:
    provider = OpenAICompatibleProvider(base_url="https://example.test/v1", api_key="key", model="model")
    monkeypatch.setattr(provider, "_post", lambda body: {"choices": [{"message": {"content": 'analysis text\n```json\n{"ok": true, "details": {"count": 2}}\n```\nfinished'}}]})

    response = provider.complete_json(prompt="return JSON", payload={})

    assert response["result"] == {"ok": True, "details": {"count": 2}}
