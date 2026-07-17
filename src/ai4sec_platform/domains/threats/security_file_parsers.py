from __future__ import annotations

import json
import re
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SA_RE = re.compile(r"(?:OpenHarmony|openEuler|openGauss|Huawei)?-?SA-\d{4}-\d{3,7}", re.I)
CVSS_RE = re.compile(r"\b([0-9](?:\.\d)?|10(?:\.0)?)\b")
SEVERITY_TERMS = {
    "critical": ["critical", "严重", "高危", "致命"],
    "high": ["high", "重要", "高"],
    "medium": ["medium", "moderate", "中"],
    "low": ["low", "低"],
}


def parse_security_file(content: str, *, source_path: str = "", source_url: str = "", repo_names: list[str] | None = None) -> list[dict[str, Any]]:
    text = content or ""
    rows = parse_markdown_table_rows(text)
    items: list[dict[str, Any]] = []
    if rows:
        for row in rows:
            row_text = " | ".join(row)
            items.extend(_items_from_text(row_text, source_path=source_path, source_url=source_url, repo_names=repo_names, source_type="security_repo_file", row=row))
    if not items:
        items.extend(_items_from_text(text, source_path=source_path, source_url=source_url, repo_names=repo_names, source_type="security_repo_file"))
    return dedupe_security_items(items)


def parse_security_json(raw: Any, *, source_path: str = "", source_url: str = "", repo_names: list[str] | None = None) -> list[dict[str, Any]]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return parse_security_file(raw, source_path=source_path, source_url=source_url, repo_names=repo_names)
    items = _walk_json(raw)
    parsed: list[dict[str, Any]] = []
    for item in items:
        parsed.extend(_items_from_text(repr(item), source_path=source_path, source_url=source_url, repo_names=repo_names, source_type="security_repo_file", row=item if isinstance(item, dict) else None))
    return dedupe_security_items(parsed)


def parse_markdown_table_rows(content: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in (content or "").splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or "|" not in stripped[1:]:
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        if not cells or all(set(cell) <= {"-", ":", " "} for cell in cells):
            continue
        rows.append(cells)
    return rows[1:] if len(rows) > 1 else rows


def dedupe_security_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped = []
    for item in items:
        key = item.get("cve_id") or item.get("sa_id") or f"{item.get('source_type')}:{item.get('description')}"
        if not key or key in seen:
            continue
        seen.add(str(key))
        deduped.append(item)
    return deduped


def _items_from_text(text: str, *, source_path: str, source_url: str, repo_names: list[str] | None, source_type: str, row: Any = None) -> list[dict[str, Any]]:
    cves = sorted({match.upper() for match in CVE_RE.findall(text or "")})
    sas = sorted({match.upper() for match in SA_RE.findall(text or "")})
    severity = infer_severity(text)
    projects = _project_hints(text, repo_names or [])
    items = []
    for cve in cves:
        items.append({"cve_id": cve, "severity": severity, "description": _compact(text), "source_type": source_type, "source_url": source_url, "source_path": source_path, "project_hints": projects, "raw_row": row})
    for sa in sas:
        items.append({"sa_id": sa, "is_sa": True, "severity": severity, "description": _compact(text), "source_type": source_type, "source_url": source_url, "source_path": source_path, "project_hints": projects, "raw_row": row})
    if not cves and not sas and _is_broad_security(text):
        items.append({"is_broad_sec": True, "severity": severity, "description": _compact(text), "source_type": source_type, "source_url": source_url, "source_path": source_path, "matched_keywords": _broad_keywords(text), "project_hints": projects, "raw_row": row})
    return items


def infer_severity(text: str) -> str:
    lowered = (text or "").lower()
    for level, terms in SEVERITY_TERMS.items():
        if any(term.lower() in lowered for term in terms):
            return level
    cvss_values = []
    for match in CVSS_RE.findall(text or ""):
        try:
            value = float(match)
        except ValueError:
            continue
        if 0 <= value <= 10:
            cvss_values.append(value)
    if cvss_values:
        score = max(cvss_values)
        if score >= 9:
            return "critical"
        if score >= 7:
            return "high"
        if score >= 4:
            return "medium"
        return "low"
    return "unknown"


def _walk_json(value: Any) -> list[Any]:
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(_walk_json(item))
        return out
    if isinstance(value, dict):
        if any(key in value for key in ["cve", "cve_id", "id", "title", "description", "summary"]):
            return [value]
        out = []
        for item in value.values():
            out.extend(_walk_json(item))
        return out
    return []


def _is_broad_security(text: str) -> bool:
    return bool(_broad_keywords(text))


def _broad_keywords(text: str) -> list[str]:
    lowered = (text or "").lower()
    terms = ["security", "vulnerability", "rce", "xss", "sqli", "bypass", "dos", "注入", "越权", "命令执行", "漏洞", "安全"]
    return [term for term in terms if term in lowered]


def _project_hints(text: str, repo_names: list[str]) -> list[str]:
    lowered = (text or "").lower()
    return [name for name in repo_names if name and name.lower() in lowered][:10]


def _compact(text: str, limit: int = 500) -> str:
    return " ".join((text or "").split())[:limit]
