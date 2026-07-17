from __future__ import annotations

from ai4sec_platform.domains.capabilities.scorers import score_capability_candidate


def rule_based_assessment(item: dict) -> dict:
    has_code = bool(item.get("code_url") or item.get("source_url") or item.get("repo_url"))
    scoring = score_capability_candidate(item)
    return {"status": "待复现验证" if has_code else "待资料补齐", "reason": "基于代码链接、论文线索、安全主题和可复现性进行本地规则评估。", "score": scoring.score, "scoring": scoring.as_payload(), "input": item}
