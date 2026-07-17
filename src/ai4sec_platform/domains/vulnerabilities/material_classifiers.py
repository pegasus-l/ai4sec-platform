from __future__ import annotations

from typing import Any

from ai4sec_platform.schemas.classification import ClassificationResult

POC_TERMS = ["poc", "exploit", "exp", "metasploit", "github.com", "复现", "利用代码", "payload"]
TECH_TERMS = ["root cause", "analysis", "逆向", "调试", "漏洞分析", "原理", "patch", "diff", "堆栈", "栈溢出", "命令执行", "rce"]
ADVISORY_TERMS = ["cve", "cnvd", "cnnvd", "advisory", "security bulletin", "公告", "漏洞通告"]
VERSION_TERMS = ["affected", "version", "影响版本", "before", "<=", "<", "修复版本"]
NOISE_TERMS = ["招聘", "培训", "广告", "目录", "登录", "403", "404"]


def classify_material(item: dict[str, Any]) -> ClassificationResult:
    text = _text(item)
    poc_hits = _hits(text, POC_TERMS)
    tech_hits = _hits(text, TECH_TERMS)
    advisory_hits = _hits(text, ADVISORY_TERMS)
    version_hits = _hits(text, VERSION_TERMS)
    noise_hits = _hits(text, NOISE_TERMS)
    if poc_hits:
        category = "PoC/Exploit"
        subcategory = "可复现素材"
    elif tech_hits:
        category = "深度技术分析"
        subcategory = "漏洞原理"
    elif advisory_hits:
        category = "漏洞公告"
        subcategory = "CVE/通告"
    elif version_hits:
        category = "影响范围线索"
        subcategory = "版本信息"
    else:
        category = "待复核素材"
        subcategory = "相关性不足"
    confidence = min(0.98, 0.25 + 0.18 * len(poc_hits) + 0.12 * len(tech_hits) + 0.1 * len(advisory_hits) + 0.08 * len(version_hits) - 0.12 * len(noise_hits))
    reasons = []
    if poc_hits:
        reasons.append(f"命中 PoC/Exploit 线索：{', '.join(poc_hits[:5])}")
    if tech_hits:
        reasons.append(f"命中技术分析线索：{', '.join(tech_hits[:5])}")
    if advisory_hits:
        reasons.append(f"命中漏洞公告线索：{', '.join(advisory_hits[:5])}")
    if version_hits:
        reasons.append("包含影响版本或修复版本线索")
    if noise_hits:
        reasons.append(f"存在噪声词：{', '.join(noise_hits[:3])}")
    return ClassificationResult(category=category, subcategory=subcategory, tags=sorted(set([category, subcategory, *poc_hits[:4], *tech_hits[:4], *advisory_hits[:4]])), confidence=round(max(0.05, confidence), 2), reasons=reasons or ["缺少明确漏洞技术线索，需要人工复核"], signals={"poc_hits": poc_hits, "tech_hits": tech_hits, "advisory_hits": advisory_hits, "version_hits": version_hits, "noise_hits": noise_hits})


def _text(item: dict[str, Any]) -> str:
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    crawl = raw.get("crawl_info") if isinstance(raw.get("crawl_info"), dict) else {}
    values = [item.get("title"), item.get("summary"), item.get("url"), item.get("category"), " ".join(item.get("key_findings") or []), raw.get("title"), raw.get("reason"), raw.get("summary"), crawl.get("markdown") or crawl.get("text")]
    return " ".join(str(value or "") for value in values).lower()


def _hits(text: str, terms: list[str]) -> list[str]:
    return [term for term in terms if term.lower() in text]
