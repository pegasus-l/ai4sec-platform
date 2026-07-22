from __future__ import annotations

from typing import Any


def build_capability_card(
    candidate: dict[str, Any],
    *,
    scoring: dict[str, Any] | None = None,
    assessment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """从候选构造 CapabilityCard payload（对齐 demo today.json / library.json 字段）。

    输入:
      candidate: 候选 dict（来自 from_news.py 的派生，含 source_news_item 反向引用）
      scoring: 评估打分结果（score + breakdown）
      assessment: LLM 评估输出（capability_type / sub_type / application_scenarios 等）

    输出: CapabilityCard payload dict，用于 repo.create_domain_item 的 payload 参数
    """
    source_news_item = candidate.get("source_news_item") or {}
    news_payload = source_news_item.get("payload") or {}
    assessment = assessment or {}
    scoring = scoring or {}

    return {
        "item_type": "capability",
        "title": candidate.get("title") or "未命名能力",
        "summary": source_news_item.get("summary") or news_payload.get("summary") or "",
        "source_url": candidate.get("source_url") or "",
        "code_url": candidate.get("code_url") or "",
        "source_type": candidate.get("source_type") or "unknown",
        "source_news_score": candidate.get("source_news_score"),
        "capability_type": assessment.get("capability_type", ""),  # 验证与评估|推理与规划|工具调用|...
        "sub_type": assessment.get("sub_type", ""),  # 幻觉缓解|代码审计|...
        "application_scenarios": assessment.get("application_scenarios", []),
        "score": scoring.get("score"),
        "score_breakdown": scoring.get("breakdown", {}),
        "summary_highlight": assessment.get("highlight", ""),
        "review": assessment.get("review", ""),
        "tech_points": news_payload.get("tech_points") or assessment.get("tech_points", []),
        "implementation_depth": {
            "has_real_code": bool(candidate.get("code_url")),
            "has_tests": assessment.get("has_tests", False),
            "has_eval": assessment.get("has_eval", False),
            "is_prompt_wrapper": assessment.get("is_prompt_wrapper", False),
            "is_thin_mcp_wrapper": assessment.get("is_thin_mcp_wrapper", False),
            "evidence": assessment.get("evidence", []),
        },
        "repro_status": "candidate" if candidate.get("code_url") else "no_code",
        "conversion_status": "未启动",
        "source_news_item": source_news_item,
    }


def build_conversion_record(
    capability_item: dict[str, Any],
    *,
    scenario: str = "",
    owner: str = "",
    next_action: str = "",
    notes: str = "",
    status: str = "持续观察",
) -> dict[str, Any]:
    """构造能力转化记录（对齐 demo conversions.json 字段）"""
    return {
        "item_type": "capability_conversion",
        "title": capability_item.get("title", "未命名能力"),
        "capability_id": capability_item.get("id"),
        "status": status,  # 持续观察|已转化|已放弃
        "scenario": scenario,
        "owner": owner,
        "next_action": next_action,
        "notes": notes,
    }
