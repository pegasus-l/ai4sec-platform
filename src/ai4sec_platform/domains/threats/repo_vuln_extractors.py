from __future__ import annotations

import re
from collections import Counter
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
SECURITY_TERMS = ["cve", "vulnerability", "security", "漏洞", "安全", "rce", "xss", "sqli", "auth bypass", "越权", "命令执行", "注入", "bypass", "dos"]
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0, "": 0}


def extract_repo_vulnerability_signals(item: dict[str, Any]) -> dict[str, Any]:
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    cve_items = _merge_security_items(item.get("cves"), raw.get("cves"))
    sa_items = _merge_security_items(item.get("sa_items"), raw.get("sa_items"))
    broad_items = _merge_security_items(item.get("broad_sec_items"), raw.get("broad_sec_items"))
    coordination_items = [entry for entry in cve_items if entry.get("association_scope") == "organization_coordination"]
    direct_items = [entry for entry in cve_items if entry.get("association_scope") != "organization_coordination"]
    cves = _extract_cves(cve_items) or _extract_cves(item, raw)
    direct_cves = _extract_cves(direct_items)
    if not cve_items:
        direct_cves = cves
    coordination_cves = _extract_cves(coordination_items)
    text = _flatten_text(item, raw).lower()
    direct_text = (text if not coordination_items else _flatten_text(direct_items, sa_items, broad_items)).lower()
    security_hits = [term for term in SECURITY_TERMS if term.lower() in text]
    severity_counts = _severity_counts([*cve_items, *sa_items, *broad_items])
    direct_severity_counts = _severity_counts([*direct_items, *sa_items, *broad_items])
    source_types = sorted({str(entry.get("source_type") or "") for entry in [*cve_items, *sa_items, *broad_items] if entry.get("source_type")})
    valid_like_items = [entry for entry in [*direct_items, *sa_items, *broad_items] if _looks_security_relevant(entry)]
    return {
        "cve_ids": cves,
        "cve_count": len(cves) or _safe_int(item.get("cve_count") or raw.get("cve_count")),
        "direct_cve_count": len(direct_cves),
        "coordination_cve_count": len(coordination_cves),
        "sa_count": len(sa_items) or _safe_int(item.get("sa_count") or raw.get("sa_count")),
        "broad_sec_count": len(broad_items) or _safe_int(item.get("broad_sec_count") or raw.get("broad_sec_count")),
        "total_sec_items": len(cve_items) + len(sa_items) + len(broad_items) or _safe_int(item.get("total_sec_items") or raw.get("total_sec_items")),
        "security_hits": security_hits,
        "severity_counts": severity_counts,
        "max_severity": _max_severity(severity_counts),
        "direct_severity_counts": direct_severity_counts,
        "direct_max_severity": _max_severity(direct_severity_counts),
        "source_types": source_types,
        "scan_mode": item.get("scan_mode") or raw.get("scan_mode") or "",
        "has_security_repo_source": any(source.startswith("security_repo") for source in source_types),
        "has_project_issue_source": any(source.startswith("project_issue") for source in source_types),
        "has_exploit_signal": any(term in direct_text for term in ["exploit", "poc", "rce", "利用", "复现"]),
        "valid_like_security_items": len(valid_like_items),
        "sample_security_items": _sample_items([*cve_items, *sa_items, *broad_items]),
    }


def _merge_security_items(*values: Any) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, list):
            continue
        for entry in value:
            if not isinstance(entry, dict):
                continue
            key = str(entry.get("cve_id") or entry.get("sa_id") or entry.get("source_url") or entry.get("description") or repr(entry))
            if key in seen:
                continue
            seen.add(key)
            merged.append(entry)
    return merged


def _extract_cves(*values: Any) -> list[str]:
    found: list[str] = []
    seen = set()
    for value in values:
        for match in CVE_RE.findall(repr(value)):
            cve = match.upper()
            if cve in seen:
                continue
            seen.add(cve)
            found.append(cve)
    return found


def _severity_counts(items: list[dict[str, Any]]) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for item in items:
        severity = str(item.get("severity") or "unknown").lower()
        counter[severity if severity in SEVERITY_ORDER else "unknown"] += 1
    return dict(counter)


def _max_severity(counts: dict[str, int]) -> str:
    if not counts:
        return "unknown"
    return max(counts, key=lambda severity: SEVERITY_ORDER.get(severity, 0))


def _looks_security_relevant(entry: dict[str, Any]) -> bool:
    text = repr(entry).lower()
    return bool(CVE_RE.search(text) or any(term.lower() in text for term in SECURITY_TERMS))


def _sample_items(items: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    sample = []
    for item in items[:limit]:
        sample.append({key: item.get(key) for key in ["cve_id", "sa_id", "severity", "description", "source_type", "source_url", "matched_keywords"] if item.get(key) is not None})
    return sample


def _flatten_text(*values: Any) -> str:
    return " ".join(repr(value) for value in values if value is not None)


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
