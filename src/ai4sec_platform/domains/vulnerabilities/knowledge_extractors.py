from __future__ import annotations

from typing import Any

from ai4sec_platform.models.local_rules import LocalRuleProvider


def extract_knowledge(item: dict[str, Any]) -> dict[str, Any]:
    return LocalRuleProvider().complete_json(prompt="漏洞知识抽取", payload=item)
