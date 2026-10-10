from __future__ import annotations

import os
import socket
import time
import urllib.error
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


class FallbackProvider:
    """把同一套模型能力在多个 provider 上的配置串成一条链:首选失败就换下一个。

    2026-10-10:DEEPSEEK 网关(az.gptplus5.com)额度耗尽,所有请求返
    「token quota is not enough」403,风险研判与能力库评审全线静默失败
    (unified_review 连续 24 小时每轮 100% 失败,run 仍记 success)。
    而 DASHSCOPE_*(阿里云 dashscope 兼容模式,模型名同为 deepseek-v4-flash-0731)
    配置完整、实测可用 —— 原来 `_configured_model` 取到第一个完整配置就返回,
    备用 provider 永远不会被用到。这类事故已经出现过四次(09-02 403、09-04 401、
    09-14 共享 key 吊销、10-10 欠费),每次都靠人发现。

    只在「这家 provider 自己出了问题」时切换:鉴权/欠费/限流(401/402/403/429)
    与连接层异常。请求本身有问题(400)不切,免得把同一个错误请求发给所有家。
    被判定为坏的 provider 会在 DEMOTE_SECONDS 内排到最后,避免每次调用都白撞一次;
    到期自动恢复,所以对方充值/换 key 后无需人工介入。
    """

    FALLBACK_STATUS = frozenset({401, 402, 403, 429})
    DEMOTE_SECONDS = 300.0

    def __init__(self, providers: list[OpenAICompatibleProvider], *, demote_seconds: float | None = None) -> None:
        if not providers:
            raise ValueError("FallbackProvider requires at least one provider")
        self._providers = list(providers)
        self._demote_seconds = self.DEMOTE_SECONDS if demote_seconds is None else demote_seconds
        self._demoted_until: dict[str, float] = {}

    # ---- 兼容:调用方会直接读这些属性(日志/探针/管理接口) ----
    @property
    def primary(self) -> OpenAICompatibleProvider:
        return self._providers[0]

    def __getattr__(self, name: str):
        providers = self.__dict__.get("_providers")
        if not providers:  # 初始化未完成时的兜底,避免无限递归
            raise AttributeError(name)
        return getattr(providers[0], name)

    def complete_json(self, *, prompt: str, payload: dict) -> dict:
        ordered = self._ordered()
        last_error: Exception | None = None
        for index, provider in enumerate(ordered):
            try:
                result = provider.complete_json(prompt=prompt, payload=payload)
            except Exception as exc:  # noqa: BLE001 —— 判断要不要换下一家
                if index >= len(ordered) - 1 or not self._should_fallback(exc):
                    raise
                self._demoted_until[provider.provider_name] = time.monotonic() + self._demote_seconds
                last_error = exc
                continue
            self._demoted_until.pop(provider.provider_name, None)
            result["provider"] = provider.provider_name
            return result
        raise last_error if last_error else RuntimeError("no provider available")  # pragma: no cover

    def _ordered(self) -> list[OpenAICompatibleProvider]:
        now = time.monotonic()
        self._demoted_until = {name: until for name, until in self._demoted_until.items() if until > now}
        return sorted(self._providers, key=lambda p: self._demoted_until.get(p.provider_name, 0.0))

    def _should_fallback(self, exc: Exception) -> bool:
        if isinstance(exc, urllib.error.HTTPError):
            return exc.code in self.FALLBACK_STATUS
        # 连接层异常(超时/DNS/TLS)也算这家不可用;网络抖动换一家通常就通了
        return isinstance(exc, (urllib.error.URLError, socket.timeout, TimeoutError, ConnectionError))


class LLMRouter:
    def __init__(self) -> None:
        load_env_file()
        self._local_rules = LocalRuleProvider()

    def provider_for(self, profile: str = "configured_model"):
        if self._force_local_rules(profile):
            return self._local_rules
        configs = self._configured_models(profile)
        if not configs:
            return self._local_rules
        providers = [
            OpenAICompatibleProvider(base_url=config.base_url, api_key=config.api_key, model=config.model, provider_name=config.provider, timeout_seconds=config.timeout_seconds, max_output_tokens=config.max_output_tokens)
            for config in configs
        ]
        return providers[0] if len(providers) == 1 else FallbackProvider(providers)

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
        configs = self._configured_models(profile)
        return configs[0] if configs else None

    def _configured_models(self, profile: str) -> list[ModelConfig]:
        """按优先级列出所有「配置完整」的 provider(首选在前),供 FallbackProvider 串链。

        同一个 provider 可能因为大小写/前缀重复出现在候选表里(如 provider 本身就叫
        DEEPSEEK),按 (base_url, model, api_key) 去重,免得同一条链上连着撞两次同一家。
        """
        provider = os.getenv("AI4SEC_MODEL_PROVIDER", profile)
        candidates = [provider, "AI4SEC_OPENAI", "OPENAI", "DEEPSEEK", "LOCAL_LLM", "DASHSCOPE"]
        configs: list[ModelConfig] = []
        seen: set[tuple[str, str, str]] = set()
        for prefix in candidates:
            normalized = prefix.upper().replace("-", "_")
            config = _config_from_prefix(normalized, profile=profile)
            if not config:
                continue
            key = (config.base_url, config.model, config.api_key)
            if key in seen:
                continue
            seen.add(key)
            configs.append(config)
        return configs


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
    default = "180" if profile in {"vulnerability_content_extractor", "vulnerability_material_reviewer", "vulnerability_knowledge_extractor"} else "45"
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
