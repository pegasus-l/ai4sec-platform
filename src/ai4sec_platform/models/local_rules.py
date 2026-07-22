from __future__ import annotations

from typing import Any


class LocalRuleProvider:
    provider_name = "local_rules"

    def complete_json(self, *, prompt: str, payload: dict) -> dict[str, Any]:
        agent = _agent_name(prompt, payload)
        if agent == "capability_assess":
            result = _assess_capability(payload)
        elif agent == "repo_summary":
            result = _repo_summary(payload)
        elif agent == "risk_reasoning":
            result = _reason_risk(payload)
        elif agent == "knowledge_extract":
            result = _extract_knowledge(payload)
        else:
            result = _summarize(payload)
        return {"provider": self.provider_name, "status": "success", "agent": agent, "result": result}


def _agent_name(prompt: str, payload: dict) -> str:
    value = f"{prompt} {payload.get('item_type', '')} {payload.get('domain', '')}".lower()
    if "代码仓摘要" in prompt or "repo_summary" in value:
        return "repo_summary"
    if "威胁" in prompt or "风险" in prompt or "risk" in value or payload.get("domain") == "threats":
        return "risk_reasoning"
    if "漏洞" in prompt or "知识" in prompt or payload.get("domain") == "vulnerabilities":
        return "knowledge_extract"
    if "能力" in prompt or "复现" in prompt or payload.get("domain") == "capabilities":
        return "capability_assess"
    return "summary"


def _assess_capability(payload: dict) -> dict[str, Any]:
    item_payload = payload.get("payload") or {}
    source_item = item_payload.get("source_news_item") or item_payload or payload
    text = " ".join(str(source_item.get(key, "")) for key in ["title", "summary", "source_url"])
    has_code = any(token in text.lower() for token in ["github.com", "gitlab", "code", "repo"])
    has_paper = any(token in text.lower() for token in ["arxiv", "paper", "论文"])
    value_score = 0.65 + (0.2 if has_code else 0) + (0.1 if has_paper else 0)
    value_score = min(value_score, 0.95)
    return {
        "value_score": round(value_score, 2),
        "reproducibility": "high" if has_code else "medium",
        "recommended_status": "待复现验证" if has_code else "待资料补齐",
        "application_scenarios": _pick_scenarios(text),
        "conversion_path": ["阅读论文/项目", "确认依赖与数据集", "复现最小样例", "沉淀检测或分析能力"],
        "reason": "基于代码链接、论文线索和安全主题命中进行本地规则评估。",
    }


def _reason_risk(payload: dict) -> dict[str, Any]:
    item_payload = payload.get("payload") or {}
    score = _safe_float(payload.get("score"), _safe_float(item_payload.get("risk_score"), 50.0))
    grade = "高" if score >= 80 else "中" if score >= 50 else "低"
    return {
        "risk_score": score,
        "risk_grade": grade,
        "recommended_status": "高风险跟踪" if score >= 80 else "持续观察" if score >= 50 else "低优先级观察",
        "signals": {
            "cve_count": item_payload.get("cve_count"),
            "stars": item_payload.get("stars"),
            "firmware_refs": item_payload.get("firmware_refs") or [],
            "mirror_refs": item_payload.get("mirror_refs") or [],
        },
        "recommended_actions": ["核对资产归属", "确认 CVE 影响版本", "检查固件/镜像暴露面", "进入人工跟踪队列" if score >= 80 else "定期刷新"],
        "reason": "基于本地 raw 归一化后的风险分、CVE/固件/镜像线索进行规则研判。",
    }


def _repo_summary(payload: dict) -> dict[str, Any]:
    repo_key = str(payload.get("title") or payload.get("repo_key") or "代码仓")
    label = repo_key.removeprefix("repo:")
    description = " ".join(str(payload.get("description_original") or "").split())
    if description:
        summary = f"{label} 代码仓：{description}"
    else:
        security = payload.get("security_summary") or "待补充仓库描述"
        summary = f"{label} 代码仓，{security}"
    return {"summary_zh": summary[:120], "confidence": 0.55, "notes": "本地规则摘要，未调用外部模型。"}


def _extract_knowledge(payload: dict) -> dict[str, Any]:
    item_payload = payload.get("payload") or {}
    findings = item_payload.get("key_findings") or []
    if not isinstance(findings, list):
        findings = [str(findings)]
    summary = payload.get("summary") or item_payload.get("summary") or payload.get("title") or "漏洞素材知识候选"
    return {
        "summary": summary,
        "key_findings": findings[:10],
        "affected_components": item_payload.get("affected_components") or item_payload.get("products") or [],
        "verification_clues": item_payload.get("verification_clues") or item_payload.get("references") or [],
        "mitigation_hints": item_payload.get("mitigation_hints") or ["确认影响版本", "复核公开 PoC", "补充检测与缓解说明"],
        "migration_status": "待人工确认",
        "reason": "基于素材摘要、关键发现和引用线索进行本地规则抽取。",
    }


def _summarize(payload: dict) -> dict[str, Any]:
    return {
        "summary": payload.get("summary") or payload.get("title") or "已完成本地规则处理。",
        "status": "success",
        "keys": sorted(str(key) for key in payload.keys())[:20],
    }


def _pick_scenarios(text: str) -> list[str]:
    lowered = text.lower()
    scenarios: list[str] = []
    if any(token in lowered for token in ["llm", "agent", "prompt", "rag"]):
        scenarios.append("AI 安全评测")
    if any(token in lowered for token in ["vuln", "cve", "exploit", "漏洞"]):
        scenarios.append("漏洞分析")
    if any(token in lowered for token in ["malware", "threat", "attack", "威胁"]):
        scenarios.append("威胁检测")
    return scenarios or ["安全自动化分析"]


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback
