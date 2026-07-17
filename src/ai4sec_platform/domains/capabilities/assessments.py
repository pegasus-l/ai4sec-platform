from __future__ import annotations


def rule_based_assessment(item: dict) -> dict:
    has_code = bool(item.get("code_url") or item.get("source_url") or item.get("repo_url"))
    return {"status": "待复现验证" if has_code else "待资料补齐", "reason": "基于代码链接和来源完整度进行本地规则评估。", "input": item}
