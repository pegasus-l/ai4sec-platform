from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from typing import Any
from urllib.parse import unquote, urlparse


_TITLE_STOPWORDS = {
    "a", "an", "and", "analysis", "blackhat", "cve", "exploit", "for", "in", "of", "on", "paper", "poc",
    "presentation", "presentations", "research", "slides", "technical", "the", "to", "us", "usa", "vulnerability",
    "wednesday", "writeup", "www",
}


def event_aggregation_key(material: dict[str, Any]) -> str:
    cve_ids = material.get("cve_ids") or material.get("extracted_evidence", {}).get("cve_ids") or []
    if len(cve_ids) == 1:
        return f"cve:{cve_ids[0]}"
    if len(cve_ids) > 1:
        return "multi-cve:" + "+".join(sorted(cve_ids))
    topic = _topic_key(material)
    return f"topic:{topic}"


def aggregate_material_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    materials: list[dict[str, Any]] = []
    for row in rows:
        payload = row.get("payload") or {}
        material = {**payload, "domain_item_id": row.get("id"), "score": row.get("score"), "status": row.get("status")}
        materials.append(material)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cluster in _cluster_research_materials(materials):
        groups[_cluster_aggregation_key(cluster)].extend(cluster)
    return [build_event_from_materials(key, materials) for key, materials in groups.items()]


def build_event_from_materials(key: str, materials: list[dict[str, Any]]) -> dict[str, Any]:
    all_cves = sorted({cve for material in materials for cve in (material.get("cve_ids") or material.get("extracted_evidence", {}).get("cve_ids") or [])})
    all_cwes = sorted({cwe for material in materials for cwe in (material.get("cwe_ids") or material.get("extracted_evidence", {}).get("cwe_ids") or [])})
    products = _top_values([product for material in materials for product in (material.get("affected_products") or material.get("extracted_evidence", {}).get("affected_products") or [])])
    versions = _top_values([version for material in materials for version in (material.get("affected_versions") or material.get("extracted_evidence", {}).get("affected_versions") or [])])
    material_ids = [int(material["domain_item_id"]) for material in materials if material.get("domain_item_id") is not None]
    evidence_types = Counter(material.get("material_type") or material.get("classification", {}).get("category") or material.get("category") or "unknown" for material in materials)
    primary = _select_primary_material(materials)
    kind = _event_kind(key, all_cves)
    event_id = _event_id(key)
    title = _event_title(kind, all_cves, primary)
    explicit_cve_material_ids = [int(material["domain_item_id"]) for material in materials if material.get("domain_item_id") is not None and _material_cves(material)]
    inferred_cve_material_ids = [material_id for material_id in material_ids if all_cves and material_id not in explicit_cve_material_ids]
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
        "research_identity": _research_identity(materials),
        "canonical_research_title": str(primary.get("title") or ""),
        "explicit_cve_material_ids": explicit_cve_material_ids,
        "inferred_cve_material_ids": inferred_cve_material_ids,
        "aggregation_confidence": _confidence(kind, materials, len(inferred_cve_material_ids)),
        "aggregation_reason": _reason(kind, all_cves, materials, len(explicit_cve_material_ids), len(inferred_cve_material_ids)),
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
    basis = _research_identity([material])
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]


def _cluster_aggregation_key(materials: list[dict[str, Any]]) -> str:
    cve_ids = sorted({cve for material in materials for cve in _material_cves(material)})
    if len(cve_ids) == 1:
        return f"cve:{cve_ids[0]}"
    if len(cve_ids) > 1:
        return "multi-cve:" + "+".join(cve_ids)
    identity = _research_identity(materials)
    return "topic:" + hashlib.sha1(identity.encode("utf-8")).hexdigest()[:16]


def _cluster_research_materials(materials: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    clusters: list[list[dict[str, Any]]] = []
    for material in materials:
        matching = [index for index, cluster in enumerate(clusters) if any(_same_research(material, member) for member in cluster)]
        if not matching:
            clusters.append([material])
            continue
        target = matching[0]
        clusters[target].append(material)
        for index in reversed(matching[1:]):
            clusters[target].extend(clusters.pop(index))
    return clusters


def _same_research(left: dict[str, Any], right: dict[str, Any]) -> bool:
    left_variants = _research_token_variants(left)
    right_variants = _research_token_variants(right)
    for left_tokens in left_variants:
        for right_tokens in right_variants:
            intersection = left_tokens & right_tokens
            if len(intersection) < 3:
                continue
            overlap = len(intersection) / min(len(left_tokens), len(right_tokens))
            jaccard = len(intersection) / len(left_tokens | right_tokens)
            if overlap >= 0.8 and jaccard >= 0.5:
                return True
    return False


def _research_token_variants(material: dict[str, Any]) -> list[set[str]]:
    raw = material.get("raw") if isinstance(material.get("raw"), dict) else {}
    metadata = material.get("metadata") if isinstance(material.get("metadata"), dict) else {}
    values = [material.get("title"), raw.get("title"), metadata.get("title")]
    url = str(material.get("url") or material.get("source_url") or "")
    if url:
        path = unquote(urlparse(url).path)
        values.extend([path, path.rsplit("/", 1)[-1]])
    variants: list[set[str]] = []
    for value in values:
        tokens = _research_tokens(str(value or ""))
        if len(tokens) >= 3 and tokens not in variants:
            variants.append(tokens)
    return variants


def _research_tokens(value: str) -> set[str]:
    normalized = value.lower()
    normalized = re.sub(r"http\s*[/_.-]?\s*1(?:\s*[/_.-]\s*1)?", " http1 ", normalized)
    tokens = re.findall(r"[a-z0-9]+", normalized)
    return {token for token in tokens if len(token) >= 3 and token not in _TITLE_STOPWORDS and not token.isdigit()}


def _research_identity(materials: list[dict[str, Any]]) -> str:
    primary = _select_primary_material(materials)
    variants = _research_token_variants(primary)
    if variants:
        preferred = max(variants, key=lambda tokens: (len(tokens), sorted(tokens)))
        return " ".join(sorted(preferred))
    title = re.sub(r"\s+", " ", str(primary.get("title") or "untitled").lower()).strip()
    return title[:160]


def _select_primary_material(materials: list[dict[str, Any]]) -> dict[str, Any]:
    def quality(material: dict[str, Any]) -> tuple[int, int, int, float]:
        title_tokens = _research_tokens(str(material.get("title") or ""))
        variants = _research_token_variants(material)
        best_variant = max((len(tokens) for tokens in variants), default=0)
        url = str(material.get("url") or material.get("source_url") or "").lower()
        preferred_page = int(not url.endswith(".pdf"))
        return len(title_tokens), preferred_page, best_variant, float(material.get("score") or 0)

    return max(materials, key=quality)


def _material_cves(material: dict[str, Any]) -> list[str]:
    return [str(cve).upper() for cve in (material.get("cve_ids") or material.get("extracted_evidence", {}).get("cve_ids") or []) if cve]


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


def _confidence(kind: str, materials: list[dict[str, Any]], inferred_cve_count: int = 0) -> float:
    if kind == "cve_event":
        return 0.92 if inferred_cve_count else 0.98
    if kind == "multi_cve_event":
        return 0.75
    return min(0.72, 0.35 + len(materials) * 0.08)


def _reason(kind: str, cve_ids: list[str], materials: list[dict[str, Any]], explicit_cve_count: int = 0, inferred_cve_count: int = 0) -> str:
    if kind == "cve_event":
        if inferred_cve_count:
            return f"同一研究的 {len(materials)} 条素材已聚类；{explicit_cve_count} 条明确包含 {cve_ids[0]}，另有 {inferred_cve_count} 条按标准标题和来源路径推断关联。"
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
