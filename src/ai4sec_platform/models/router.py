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
        return OpenAICompatibleProvider(base_url=config.base_url, api_key=config.api_key, model=config.model, provider_name=config.provider)

    def complete_json(self, *, profile: str = "configured_model", prompt: str, payload: dict) -> dict:
        return self.provider_for(profile).complete_json(prompt=prompt, payload=payload)

    def active_config(self, profile: str = "configured_model") -> dict[str, str | bool]:
        if self._force_local_rules(profile):
            return {"provider": "local_rules", "configured": True, "model": "offline-rule-engine"}
        config = self._configured_model(profile)
        if not config:
            return {"provider": "local_rules", "configured": False, "model": "offline-rule-engine"}
        return {"provider": config.provider, "configured": True, "model": config.model, "base_url": config.base_url}

    def _force_local_rules(self, profile: str) -> bool:
        provider = os.getenv("AI4SEC_MODEL_PROVIDER", profile)
        if provider in {"local_rules", "rule_based", "offline"}:
            return True
        if os.getenv("PYTEST_CURRENT_TEST") and os.getenv("AI4SEC_ALLOW_REAL_MODEL_IN_TESTS") != "1":
            return True
        return False

    def _configured_model(self, profile: str) -> ModelConfig | None:
        provider = os.getenv("AI4SEC_MODEL_PROVIDER", profile)
        candidates = [provider, "AI4SEC_OPENAI", "DEEPSEEK", "LOCAL_LLM", "DASHSCOPE"]
        for prefix in candidates:
            normalized = prefix.upper().replace("-", "_")
            config = _config_from_prefix(normalized)
            if config:
                return config
        return None


def _config_from_prefix(prefix: str) -> ModelConfig | None:
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
    return ModelConfig(provider=prefix.lower(), base_url=base_url, api_key=api_key, model=model)
