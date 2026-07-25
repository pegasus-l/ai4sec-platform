from ai4sec_platform.models.router import _config_from_prefix


def test_configured_model_timeout_defaults_and_is_bounded(monkeypatch) -> None:
    monkeypatch.setenv("DASHSCOPE_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("DASHSCOPE_API_KEY", "test-key")
    monkeypatch.setenv("DASHSCOPE_MODEL", "test-model")
    monkeypatch.delenv("AI4SEC_MODEL_TIMEOUT_SECONDS", raising=False)

    assert _config_from_prefix("DASHSCOPE").timeout_seconds == 45.0
    assert _config_from_prefix("DASHSCOPE").max_output_tokens == 4096
    knowledge_config = _config_from_prefix("DASHSCOPE", profile="vulnerability_knowledge_extractor")
    assert knowledge_config.timeout_seconds == 180.0
    assert knowledge_config.max_output_tokens == 4096
    content_config = _config_from_prefix("DASHSCOPE", profile="vulnerability_content_extractor")
    assert content_config.timeout_seconds == 600.0
    assert content_config.max_output_tokens == 16384
    review_config = _config_from_prefix("DASHSCOPE", profile="vulnerability_material_reviewer")
    assert review_config.timeout_seconds == 180.0
    assert review_config.max_output_tokens == 2048

    monkeypatch.setenv("AI4SEC_MODEL_TIMEOUT_SECONDS", "999")
    assert _config_from_prefix("DASHSCOPE").timeout_seconds == 600.0

    monkeypatch.setenv("AI4SEC_MODEL_TIMEOUT_SECONDS", "1")
    assert _config_from_prefix("DASHSCOPE").timeout_seconds == 5.0

    monkeypatch.setenv("AI4SEC_MODEL_MAX_OUTPUT_TOKENS", "99999")
    assert _config_from_prefix("DASHSCOPE").max_output_tokens == 65536
