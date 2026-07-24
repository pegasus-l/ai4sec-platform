from __future__ import annotations

from typing import Any

from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.router import LLMRouter

KNOWLEDGE_EXTRACT_PROMPT = """你是漏洞知识工程专家。请把漏洞素材/事件提炼为结构化漏洞知识，用于安全大模型知识库。
请以 JSON 返回：
{
  "vulnerability_type": "漏洞类型",
  "cve_ids": ["CVE-YYYY-NNNN"],
  "cwe_ids": ["CWE-NNN"],
  "root_cause_pattern": "根因模式",
  "trigger_condition": "触发条件",
  "attack_entry": "攻击入口",
  "key_functions_or_apis": ["函数/API/协议字段"],
  "exploit_primitives": ["利用原语/能力边界"],
  "mitigation_or_fix": "修复/缓解方式",
  "code_search_keywords": ["代码搜索关键词"],
  "evidence_refs": {"字段名": ["证据片段或来源"]},
  "field_confidence": {"字段名": 0.0-1.0}
}。
如果字段不确定，请保留“待复核/待确认”，不要编造。"""


def extract_knowledge(item: dict[str, Any]) -> dict[str, Any]:
    try:
        provider = LLMRouter().provider_for("vulnerability_knowledge_extractor")
        if not isinstance(provider, LocalRuleProvider):
            response = provider.complete_json(prompt=KNOWLEDGE_EXTRACT_PROMPT, payload=_knowledge_payload(item))
            result = response.get("result") or response.get("parsed") or {}
            if isinstance(result, dict) and result:
                return {"provider": response.get("provider"), "status": "success", "agent": "knowledge_extract", "model": response.get("model"), "prompt": KNOWLEDGE_EXTRACT_PROMPT, "result": {**result, "model_used": True}}
    except Exception as exc:  # pragma: no cover - external model dependent
        local = LocalRuleProvider().complete_json(prompt="漏洞知识抽取", payload=item)
        local["result"] = {**(local.get("result") or {}), "model_used": False, "llm_error": str(exc)[:300]}
        return local
    local = LocalRuleProvider().complete_json(prompt="漏洞知识抽取", payload=item)
    local["result"] = {**(local.get("result") or {}), "model_used": False}
    return local


def _knowledge_payload(item: dict[str, Any]) -> dict[str, Any]:
    payload = item.get("payload") or {}
    return {
        "title": item.get("title"),
        "summary": item.get("summary"),
        "status": item.get("status"),
        "score": item.get("score"),
        "payload": payload,
        "text": "\n".join(str(value) for value in [item.get("title"), item.get("summary"), payload.get("summary"), payload.get("check_reason"), payload.get("cleaned_text"), payload.get("markdown"), "\n".join(payload.get("key_findings") or [])] if value)[:24000],
    }
