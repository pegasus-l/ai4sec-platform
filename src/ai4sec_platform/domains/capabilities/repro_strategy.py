from __future__ import annotations

from dataclasses import dataclass
from typing import Any


LOCAL_REPRO_STRATEGIES = frozenset({"local_web", "cli"})
REQUESTED_REPRO_STRATEGIES = frozenset({"auto", *LOCAL_REPRO_STRATEGIES})


@dataclass(frozen=True)
class ReproStrategyDecision:
    strategy: str
    reason: str
    demo_url: str = ""

    @property
    def should_enqueue(self) -> bool:
        return self.strategy in LOCAL_REPRO_STRATEGIES


def resolve_repro_strategy(item: dict[str, Any], requested_strategy: str = "auto") -> ReproStrategyDecision:
    if requested_strategy not in REQUESTED_REPRO_STRATEGIES:
        raise ValueError(f"unknown requested reproduction strategy: {requested_strategy}")
    if requested_strategy in LOCAL_REPRO_STRATEGIES:
        return ReproStrategyDecision(requested_strategy, "operator explicitly selected local execution")

    payload = item.get("payload") or {}
    configured = str(payload.get("repro_strategy") or "").strip()
    demo_url = str(payload.get("demo_url") or "").strip()
    demo_verified = payload.get("demo_verified") is True
    if configured == "official_demo" and demo_url and demo_verified:
        return ReproStrategyDecision("official_demo", "verified official demo is preferred over duplicate local deployment", demo_url)
    if configured == "unsupported":
        return ReproStrategyDecision("unsupported", str(payload.get("repro_strategy_reason") or "project is explicitly marked as not locally reproducible"))
    if configured in LOCAL_REPRO_STRATEGIES:
        return ReproStrategyDecision(configured, "persisted project classification")
    implementation = payload.get("implementation_depth") or {}
    if implementation.get("has_real_code") is False:
        return ReproStrategyDecision("unsupported", "project does not contain a real executable implementation")
    if demo_url and demo_verified:
        return ReproStrategyDecision("official_demo", "verified official demo is preferred over duplicate local deployment", demo_url)
    if payload.get("is_web") is True:
        return ReproStrategyDecision("local_web", "project classification identifies a built-in Web interface")
    return ReproStrategyDecision("cli", "no verified Web interface; validate the documented CLI or minimal example")
