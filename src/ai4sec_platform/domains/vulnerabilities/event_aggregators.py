from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from typing import Any


def event_aggregation_key(material: dict[str, Any]) -> str:
    cve_ids = material.get("cve_ids") or material.get("extracted_evidence", {}).get("cve_ids") or []
    if len(cve_ids) == 1:
        return f"cve:{cve_ids[0]}"
    if len(cve_ids) > 1:
        return "multi-cve:" + "+".join(sorted(cve_ids))
    topic = _topic_key(material)
    return f"topic:{topic}"


def aggregate_material_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        payload = row.get("payload") or {}
        material = {**payload, "domain_item_id": row.get("id"), "score": row.get("score"), "status": row.get("status")}
        groups[event_aggregation_key(material)].append(material)
    return [build_event_from_materials(key, materials) for key, materials in groups.items()]


def build_event_from_materials(key: str, materials: list[dict[str, Any]]) -> dict[str, Any]:
    all_cves = sorted({cve for material in materials for cve in (material.get("cve_ids") or material.get("extracted_evidence", {}).get("cve_ids") or [])})
    all_cwes = sorted({cwe for material in materials for cwe in (material.get("cwe_ids") or material.get("extracted_evidence", {}).get("cwe_ids") or [])})
    products = _top_values([product for material in materials for product in (material.get("affected_products") or material.get("extracted_evidence", {}).get("affected_products") or [])])
    versions = _top_values([version for material in materials for version in (material.get("affected_versions") or material.get("extracted_evidence", {}).get("affected_versions") or [])])
    material_ids = [int(material["domain_item_id"]) for material in materials if material.get("domain_item_id") is not None]
    evidence_types = Counter(material.get("material_type") or material.get("classification", {}).get("category") or material.get("category") or "unknown" for material in materials)
    primary = materials[0]
    kind = _event_kind(key, all_cves)
    event_id = _event_id(key)
    title = _event_title(kind, all_cves, primary)
    return {
        "event_id": event_id,
        "title": title,
        "kind": kind,
        "cve_ids": all_cves,
        "primary_cve_id": all_cves[0] if len(all_cves) == 1 else None,
        "cwe_ids": all_cwes,
        "severity": _severity(primary),
        "affected_products": products,
        "affected_versions": versions,
        "components": products,
        "attack_entry": _attack_entry(primary),
        "root_cause_summary": _root_cause(primary),
        "material_ids": material_ids,
        "evidence_types": dict(evidence_types),
        "aggregation_key": key,
        "aggregation_confidence": _confidence(kind, materials),
        "aggregation_reason": _reason(kind, all_cves, materials),
        "knowledge_completeness": _knowledge_completeness(materials),
        "status": "ready_for_extraction" if all_cves else "needs_review",
        "latest_update_at": max([str(material.get("primary_date") or material.get("crawled_at") or "") for material in materials] or [""]),
    }


def _event_kind(key: str, cve_ids: list[str]) -> str:
    if key.startswith("cve:"):
        return "cve_event"
    if key.startswith("multi-cve:") or len(cve_ids) > 1:
        return "multi_cve_event"
    if key.startswith("topic:"):
        return "knowledge_topic"
    return "research_event"


def _event_title(kind: str, cve_ids: list[str], material: dict[str, Any]) -> str:
    title = material.get("title") or "未命名漏洞事件"
    if kind == "cve_event" and cve_ids:
        return f"{cve_ids[0]} · {title}"
    if kind == "multi_cve_event" and cve_ids:
        return f"多 CVE 事件 · {', '.join(cve_ids[:3])}"
    return title


def _event_id(key: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9_.:-]+", "-", key.lower()).strip("-")
    if len(safe) <= 64:
        return f"evt-{safe}"
    digest = hashlib.sha1(key.encode("utf-8")).hexdigest()[:12]
    return f"evt-{digest}"


def _topic_key(material: dict[str, Any]) -> str:
    products = material.get("affected_products") or material.get("extracted_evidence", {}).get("affected_products") or []
    indicators = material.get("extracted_evidence", {}).get("technical_indicators") or []
    category = material.get("material_type") or material.get("classification", {}).get("category") or material.get("category") or "unknown"
    title = str(material.get("title") or "")[:80].lower()
    basis = ":".join([*(str(x).lower() for x in products[:2]), *(str(x).lower() for x in indicators[:2]), str(category).lower(), title])
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


def _top_values(values: list[str], limit: int = 8) -> list[str]:
    return [value for value, _ in Counter(value for value in values if value).most_common(limit)]


def _severity(material: dict[str, Any]) -> str:
    text = f"{material.get('title', '')} {material.get('summary', '')}".lower()
    if any(term in text for term in ["rce", "kernel code execution", "critical", "命令执行"]):
        return "Critical"
    if any(term in text for term in ["privilege", "uaf", "oob", "高危"]):
        return "High"
    return "Unknown"


def _attack_entry(material: dict[str, Any]) -> str:
    products = material.get("affected_products") or material.get("extracted_evidence", {}).get("affected_products") or []
    if products:
        return products[0]
    classification = material.get("classification", {})
    return classification.get("subcategory") or classification.get("category") or "待抽取"


def _root_cause(material: dict[str, Any]) -> str:
    snippets = material.get("extracted_evidence", {}).get("evidence_snippets") or []
    for snippet in snippets:
        if snippet.get("snippet_type") == "root_cause":
            return snippet.get("content", "")[:260]
    return str(material.get("summary") or "待抽取根因")[:260]


def _confidence(kind: str, materials: list[dict[str, Any]]) -> float:
    if kind == "cve_event":
        return 0.98
    if kind == "multi_cve_event":
        return 0.75
    return min(0.72, 0.35 + len(materials) * 0.08)


def _reason(kind: str, cve_ids: list[str], materials: list[dict[str, Any]]) -> str:
    if kind == "cve_event":
        return f"按 CVE 主键 {cve_ids[0]} 聚合 {len(materials)} 条素材。"
    if kind == "multi_cve_event":
        return f"素材同时包含多个 CVE：{', '.join(cve_ids)}，需要人工确认是否拆分。"
    return "未发现明确 CVE，按组件、分类、标题和技术指标建立知识主题，需人工抽样审核。"


def _knowledge_completeness(materials: list[dict[str, Any]]) -> float:
    if not materials:
        return 0.0
    material = materials[0]
    evidence = material.get("extracted_evidence") or {}
    score = 0.15
    for key in ["cve_ids", "cwe_ids", "affected_products", "affected_versions", "technical_indicators", "evidence_snippets"]:
        if evidence.get(key) or material.get(key):
            score += 0.13
    return round(min(score, 0.95), 2)
