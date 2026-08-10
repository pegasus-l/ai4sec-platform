"""关键词分类器——双轨制：安全 + 通用Agent技术，不偏袒安全类。"""
from __future__ import annotations
from typing import Any
from ai4sec_platform.schemas.classification import ClassificationResult

# 通用 Agent 技术关键词（和安全的同等权重）
AGENT_TECH_TERMS = [
    # 工具调用
    "mcp", "function call", "tool use", "tool calling", "code interpreter",
    # 记忆管理
    "rag", "retrieval", "memory", "knowledge graph", "context window", "long-term memory",
    # 推理规划
    "chain of thought", "tree of thought", "reflection", "planning", "reasoning", "cot",
    # 多Agent
    "multi-agent", "multi agent", "agent collaboration", "orchestration", "manager worker",
    # 自进化
    "self-improve", "dspy", "textgrad", "skill learning", "self-evolv", "auto prompt",
    # 框架/平台
    "langchain", "langgraph", "autogen", "crewai", "agentuniverse", "llama-index",
]

# 安全关键词
SECURITY_TERMS = [
    "ai security", "llm security", "agent security", "prompt injection", "jailbreak",
    "model extraction", "ai for security", "ai for sec", "security agent",
    "安全", "漏洞", "攻防", "恶意软件", "入侵检测", "红队", "蓝队",
]

VULN_TERMS = ["cve", "vulnerability", "exploit", "poc", "rce", "漏洞", "利用", "复现"]

CODE_TERMS = ["github.com", "gitlab", "code", "repo", "repository", "开源", "clone"]

LOW_SIGNAL_TERMS = ["leaderboard", "weekly roundup", "sponsored", "newsletter", "招聘"]


def classify_item(item: dict[str, Any]) -> ClassificationResult:
    """分类 + security_flag 标记。不偏袒安全类——命中任何技术关键词都加分。"""
    text = _text(item).lower()
    agent_hits = _hits(text, AGENT_TECH_TERMS)
    security_hits = _hits(text, SECURITY_TERMS)
    vuln_hits = _hits(text, VULN_TERMS)
    code_hits = _hits(text, CODE_TERMS)
    low_signal_hits = _hits(text, LOW_SIGNAL_TERMS)

    source_type = item.get("source_type") or item.get("payload", {}).get("source_type") or "article"

    # 分类：优先看命中哪类关键词，不偏安全
    if vuln_hits:
        category, subcategory = "漏洞与攻防", "漏洞利用/PoC" if any(t in vuln_hits for t in ["exploit", "poc", "利用", "复现"]) else "漏洞研究"
    elif agent_hits:
        category, subcategory = "Agent技术", _agent_subcategory(agent_hits)
    elif security_hits:
        category, subcategory = "AI安全研究", "论文/文章"
    elif source_type in ("project", "github") or code_hits:
        category, subcategory = "开源工具与代码", "开源仓库"
    else:
        category, subcategory = "待复核", source_type

    # confidence：命中任何技术关键词都加分（安全+通用等价）
    confidence = min(0.95, 0.35
                     + 0.12 * len(agent_hits)
                     + 0.10 * len(security_hits)
                     + 0.08 * len(vuln_hits)
                     + 0.05 * len(code_hits)
                     - 0.04 * len(low_signal_hits))

    security_flag = bool(security_hits or vuln_hits)
    security_topics = sorted(set(security_hits[:5] + vuln_hits[:3]))
    tags = sorted(set([source_type, category, *agent_hits[:5], *security_hits[:4], *code_hits[:3]]))
    reasons = []
    if agent_hits:
        reasons.append(f"命中 Agent 技术关键词：{', '.join(agent_hits[:5])}")
    if security_hits:
        reasons.append(f"命中安全关键词：{', '.join(security_hits[:5])}")
    if code_hits or source_type in ("project", "github"):
        reasons.append("包含代码或仓库线索")
    if not reasons:
        reasons.append("未命中强技术关键词，需要人工复核")

    return ClassificationResult(
        category=category,
        subcategory=subcategory,
        tags=tags,
        confidence=round(max(0.05, confidence), 2),
        reasons=reasons,
        signals={
            "source_type": source_type,
            "agent_tech_hits": agent_hits,
            "security_hits": security_hits,
            "vuln_hits": vuln_hits,
            "code_hits": code_hits,
            "low_signal_hits": low_signal_hits,
            "security_flag": security_flag,
            "security_topics": security_topics,
        },
    )


def _agent_subcategory(hits: list[str]) -> str:
    text = " ".join(hits).lower()
    if any(t in text for t in ["mcp", "function call", "tool"]):
        return "工具调用"
    if any(t in text for t in ["rag", "memory", "knowledge graph", "context"]):
        return "记忆与上下文管理"
    if any(t in text for t in ["chain of thought", "tree of thought", "reflection", "planning", "reasoning", "cot"]):
        return "推理与规划"
    if any(t in text for t in ["multi-agent", "collaboration", "orchestration"]):
        return "多Agent协作"
    if any(t in text for t in ["dspy", "textgrad", "self-improve", "skill", "self-evolv", "auto prompt"]):
        return "自进化"
    return "Agent框架/平台"


def _hits(text: str, terms: list[str]) -> list[str]:
    return [term for term in terms if term in text]


def _text(item: dict[str, Any]) -> str:
    payload = item.get("payload") or item.get("normalized") or item
    values = [payload.get("title"), payload.get("summary"), payload.get("abstract"),
              payload.get("description"), payload.get("url"), payload.get("code_url")]
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    values.extend([raw.get("title"), raw.get("summary"), raw.get("description")])
    return " ".join(str(v or "") for v in values)
