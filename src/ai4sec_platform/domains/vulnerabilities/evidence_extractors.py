from __future__ import annotations

import hashlib
from typing import Any

from ai4sec_platform.domains.vulnerabilities.entity_normalizers import enrich_material_entities, material_text


def extract_material_evidence(item: dict[str, Any]) -> dict[str, Any]:
    enriched = enrich_material_entities(item)
    text = material_text(enriched)
    lowered = text.lower()
    return {
        "cve_ids": enriched.get("cve_ids", []),
        "cwe_ids": enriched.get("cwe_ids", []),
        "affected_versions": enriched.get("affected_versions", []),
        "affected_products": enriched.get("affected_products", []),
        "has_poc": any(term in lowered for term in ["poc", "exploit", "复现", "利用代码", "payload"]),
        "has_mitigation": any(term in lowered for term in ["patch", "fix", "mitigation", "修复", "缓解"]),
        "technical_indicators": [term for term in ["rce", "xss", "sqli", "auth bypass", "命令执行", "越权", "反序列化", "uaf", "oob"] if term in lowered],
        "evidence_snippets": extract_evidence_snippets(enriched),
    }


def extract_evidence_snippets(item: dict[str, Any]) -> list[dict[str, Any]]:
    text = material_text(item)
    snippets: list[dict[str, Any]] = []
    terms = {
        "root_cause": ["root cause", "根因", "原因", "导致", "because", "due to"],
        "trigger": ["trigger", "触发", "when", "条件", "payload", "request"],
        "poc": ["poc", "exploit", "payload", "复现", "利用"],
        "patch": ["patch", "fix", "mitigation", "修复", "缓解"],
        "affected_version": ["affected", "version", "影响版本", "fixed in", "修复版本"],
    }
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for snippet_type, needles in terms.items():
        for line in lines:
            lowered = line.lower()
            if any(needle.lower() in lowered for needle in needles):
                snippets.append(_snippet(item, snippet_type, line))
                break
    if not snippets and item.get("summary"):
        snippets.append(_snippet(item, "summary", str(item.get("summary"))))
    return snippets[:8]


def _snippet(item: dict[str, Any], snippet_type: str, content: str) -> dict[str, Any]:
    material_key = item.get("item_key") or item.get("material_id") or item.get("url") or item.get("title") or "material"
    digest = hashlib.sha1(f"{material_key}:{snippet_type}:{content}".encode("utf-8")).hexdigest()[:12]
    return {
        "snippet_id": f"ev-{digest}",
        "snippet_type": snippet_type,
        "title": f"{snippet_type} evidence",
        "content": content[:1200],
        "source_url": item.get("url") or item.get("source_url") or "",
        "confidence": 0.7 if snippet_type != "summary" else 0.45,
        "extracted_by": "rule",
    }
