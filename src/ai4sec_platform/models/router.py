from __future__ import annotations

import os
from dataclasses import dataclass

from ai4sec_platform.core.env import load_env_file
from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.openai_compatible import OpenAICompatibleProvider


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    base_url: str
    api_key: str
    model: str
    timeout_seconds: float
    max_output_tokens: int


class LLMRouter:
    def __init__(self) -> None:
        load_env_file()
        self._local_rules = LocalRuleProvider()

    def provider_for(self, profile: str = "configured_model"):
        if self._force_local_rules(profile):
            return self._local_rules
        config = self._configured_model(profile)
        if not config:
            return self._local_rules
        return OpenAICompatibleProvider(base_url=config.base_url, api_key=config.api_key, model=config.model, provider_name=config.provider, timeout_seconds=config.timeout_seconds, max_output_tokens=config.max_output_tokens)

    def complete_json(self, *, profile: str = "configured_model", prompt: str, payload: dict) -> dict:
        return self.provider_for(profile).complete_json(prompt=prompt, payload=payload)

    def active_config(self, profile: str = "configured_model") -> dict[str, str | bool]:
        if self._force_local_rules(profile):
            return {"provider": "local_rules", "configured": True, "model": "offline-rule-engine"}
        config = self._configured_model(profile)
        if not config:
            return {"provider": "local_rules", "configured": False, "model": "offline-rule-engine"}
        return {"provider": config.provider, "configured": True, "model": config.model, "base_url": config.base_url, "timeout_seconds": config.timeout_seconds, "max_output_tokens": config.max_output_tokens}

    def _force_local_rules(self, profile: str) -> bool:
        if profile in {"local_rules", "rule_based", "offline"}:
            return True
        provider = os.getenv("AI4SEC_MODEL_PROVIDER", profile)
        if provider in {"local_rules", "rule_based", "offline"}:
            return True
        if os.getenv("PYTEST_CURRENT_TEST") and os.getenv("AI4SEC_ALLOW_REAL_MODEL_IN_TESTS") != "1":
            return True
        return False

    def _configured_model(self, profile: str) -> ModelConfig | None:
        provider = os.getenv("AI4SEC_MODEL_PROVIDER", profile)
        candidates = [provider, "AI4SEC_OPENAI", "OPENAI", "DEEPSEEK", "LOCAL_LLM", "DASHSCOPE"]
        for prefix in candidates:
            normalized = prefix.upper().replace("-", "_")
            config = _config_from_prefix(normalized, profile=profile)
            if config:
                return config
        return None


def _config_from_prefix(prefix: str, *, profile: str = "configured_model") -> ModelConfig | None:
    if prefix in {"CONFIGURED_MODEL", "OPENAI_COMPATIBLE"}:
        prefix = "AI4SEC_OPENAI"
    base_url = os.getenv(f"{prefix}_BASE_URL", "")
    api_key = os.getenv(f"{prefix}_API_KEY", "")
    model = os.getenv(f"{prefix}_MODEL", "")
    if prefix == "DASHSCOPE" and base_url and api_key and not model:
        model = os.getenv("DASHSCOPE_MODEL", "qwen-plus")
    if prefix == "LOCAL_LLM" and base_url and api_key and not model:
        model = os.getenv("LOCAL_LLM_MODEL", "local-model")
    if not base_url or not api_key or not model:
        return None
    return ModelConfig(provider=prefix.lower(), base_url=base_url, api_key=api_key, model=model, timeout_seconds=_model_timeout_seconds(profile), max_output_tokens=_model_max_output_tokens(profile))


def _model_timeout_seconds(profile: str) -> float:
    profile_key = _profile_key(profile)
    if profile == "vulnerability_content_extractor":
        default = "600"
    elif profile in {"vulnerability_material_reviewer", "vulnerability_knowledge_extractor"}:
        default = "180"
    else:
        default = "45"
    try:
        timeout = float(os.getenv(f"AI4SEC_{profile_key}_TIMEOUT_SECONDS", os.getenv("AI4SEC_MODEL_TIMEOUT_SECONDS", default)))
    except ValueError:
        timeout = float(default)
    return min(max(timeout, 5.0), 600.0)


def _model_max_output_tokens(profile: str) -> int:
    profile_key = _profile_key(profile)
    default = "16384" if profile == "vulnerability_content_extractor" else "4096" if profile == "vulnerability_knowledge_extractor" else "2048" if profile == "vulnerability_material_reviewer" else "4096"
    try:
        max_tokens = int(os.getenv(f"AI4SEC_{profile_key}_MAX_OUTPUT_TOKENS", os.getenv("AI4SEC_MODEL_MAX_OUTPUT_TOKENS", default)))
    except ValueError:
        max_tokens = int(default)
    return min(max(max_tokens, 256), 65536)


def _profile_key(profile: str) -> str:
    return profile.upper().replace("-", "_")
