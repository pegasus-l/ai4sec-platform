from ai4sec_platform.models.router import _config_from_prefix


def test_configured_model_timeout_defaults_and_is_bounded(monkeypatch) -> None:
    monkeypatch.setenv("DASHSCOPE_BASE_URL", "https://example.test/v1")
    monkeypatch.setenv("DASHSCOPE_API_KEY", "test-key")
    monkeypatch.setenv("DASHSCOPE_MODEL", "test-model")
    # 这里量的是**代码里的默认值**, 所以 .env 里能盖掉它的每一层都要清掉:
    # 全局那两个, 以及每个 profile 自己的 `AI4SEC_<PROFILE>_TIMEOUT_SECONDS` /
    # `..._MAX_OUTPUT_TOKENS`(部署机的 .env 就配了 profile 级的)。
    # 不清的话, 同一份代码在不同机器上跑出不同结果, 红的那台看着像代码坏了。
    profiles = ("vulnerability_knowledge_extractor", "vulnerability_content_extractor",
                "vulnerability_material_reviewer")
    for key in ("AI4SEC_MODEL_TIMEOUT_SECONDS", "AI4SEC_MODEL_MAX_OUTPUT_TOKENS"):
        monkeypatch.delenv(key, raising=False)
    for profile in profiles:
        profile_key = profile.upper()
        for suffix in ("TIMEOUT_SECONDS", "MAX_OUTPUT_TOKENS"):
            monkeypatch.delenv(f"AI4SEC_{profile_key}_{suffix}", raising=False)

    assert _config_from_prefix("DASHSCOPE").timeout_seconds == 45.0
    assert _config_from_prefix("DASHSCOPE").max_output_tokens == 4096
    knowledge_config = _config_from_prefix("DASHSCOPE", profile="vulnerability_knowledge_extractor")
    assert knowledge_config.timeout_seconds == 180.0
    assert knowledge_config.max_output_tokens == 4096
    content_config = _config_from_prefix("DASHSCOPE", profile="vulnerability_content_extractor")
    # content 抽取也是 180s 档(和 knowledge / reviewer 同档);600 是**上限**,不是默认值。
    assert content_config.timeout_seconds == 180.0
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
