from __future__ import annotations

import re
from typing import Any

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
SECURITY_TERMS = ["cve", "vulnerability", "security", "漏洞", "安全", "rce", "xss", "sqli", "auth bypass", "越权", "命令执行"]


def extract_repo_vulnerability_signals(item: dict[str, Any]) -> dict[str, Any]:
    raw = item.get("raw") if isinstance(item.get("raw"), dict) else {}
    cves = _extract_cves(item, raw)
    text = _flatten_text(item, raw).lower()
    security_hits = [term for term in SECURITY_TERMS if term.lower() in text]
    advisories = _listify(raw.get("advisories") or raw.get("security_advisories"))
    issues = _listify(raw.get("issues") or raw.get("security_issues"))
    return {
        "cve_ids": cves,
        "cve_count": len(cves),
        "security_hits": security_hits,
        "advisory_count": len(advisories),
        "security_issue_count": len(issues),
        "has_exploit_signal": any(term in text for term in ["exploit", "poc", "rce", "利用", "复现"]),
    }


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


def _flatten_text(*values: Any) -> str:
    return " ".join(repr(value) for value in values if value is not None)


def _listify(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []
