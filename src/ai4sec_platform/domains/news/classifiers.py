from __future__ import annotations

from typing import Any

from ai4sec_platform.schemas.classification import ClassificationResult

AI_SECURITY_TERMS = [
    "ai security", "llm security", "agent security", "prompt injection", "jailbreak", "model extraction",
    "ai for security", "ai for sec", "security agent", "安全", "漏洞", "攻防", "恶意软件", "入侵检测",
]
VULN_TERMS = ["cve", "vulnerability", "exploit", "poc", "rce", "漏洞", "利用", "复现"]
AGENT_TERMS = ["agent", "multi-agent", "tool use", "mcp", "autonomous", "智能体"]
CODE_TERMS = ["github.com", "gitlab", "code", "repo", "repository", "开源"]
LOW_SIGNAL_TERMS = ["leaderboard", "weekly roundup", "sponsored"]


def classify_news_item(item: dict[str, Any]) -> ClassificationResult:
    text = _text(item)
    hits = _hits(text, AI_SECURITY_TERMS)
    vuln_hits = _hits(text, VULN_TERMS)
    agent_hits = _hits(text, AGENT_TERMS)
    code_hits = _hits(text, CODE_TERMS)
    low_signal_hits = _hits(text, LOW_SIGNAL_TERMS)
    source_type = item.get("source_type") or item.get("payload", {}).get("source_type") or "article"
    if vuln_hits:
        category = "漏洞与攻防"
        subcategory = "漏洞利用/PoC" if any(term in vuln_hits for term in ["exploit", "poc", "利用", "复现"]) else "漏洞研究"
    elif agent_hits:
        category = "Agent 安全"
        subcategory = "智能体/工具调用安全"
    elif source_type == "project" or code_hits:
        category = "安全工具与代码"
        subcategory = "开源仓库"
    elif hits:
        category = "AI 安全研究"
        subcategory = "论文/文章"
    else:
        category = "待复核"
        subcategory = source_type
    confidence = min(0.95, 0.35 + 0.12 * len(hits) + 0.1 * len(vuln_hits) + 0.08 * len(agent_hits) + 0.05 * len(code_hits) - 0.04 * len(low_signal_hits))
    tags = sorted(set([source_type, category, *hits[:5], *vuln_hits[:4], *agent_hits[:4]]))
    reasons = []
    if hits:
        reasons.append(f"命中 AI 安全关键词：{', '.join(hits[:5])}")
    if vuln_hits:
        reasons.append(f"命中漏洞/攻防关键词：{', '.join(vuln_hits[:5])}")
    if code_hits or source_type == "project":
        reasons.append("包含代码或仓库线索")
    if not reasons:
        reasons.append("未命中强安全关键词，需要人工复核")
    return ClassificationResult(category=category, subcategory=subcategory, tags=tags, confidence=round(max(0.05, confidence), 2), reasons=reasons, signals={"source_type": source_type, "ai_security_hits": hits, "vuln_hits": vuln_hits, "agent_hits": agent_hits, "code_hits": code_hits, "low_signal_hits": low_signal_hits})


def _text(item: dict[str, Any]) -> str:
    payload = item.get("payload") or item.get("normalized") or item
    values = [payload.get("title"), payload.get("summary"), payload.get("abstract"), payload.get("description"), payload.get("url"), payload.get("code_url")]
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    values.extend([raw.get("title"), raw.get("summary"), raw.get("description")])
    return " ".join(str(value or "") for value in values).lower()


def _hits(text: str, terms: list[str]) -> list[str]:
    return [term for term in terms if term.lower() in text]
