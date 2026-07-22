from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.threats.security_file_parsers import broad_security_keywords, dedupe_security_items, infer_severity
from ai4sec_platform.domains.threats.security_file_parsers import CVE_RE, SA_RE


def extract_security_items_from_issues(issues: list[dict[str, Any]], *, source_type: str = "project_issue") -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for issue in issues or []:
        if not isinstance(issue, dict):
            continue
        title = str(issue.get("title") or issue.get("name") or "")
        body = str(issue.get("body") or issue.get("description") or issue.get("content") or "")
        text = f"{title}\n{body}"
        severity = infer_severity(text)
        source_url = str(issue.get("html_url") or issue.get("url") or issue.get("source_url") or "")
        cves = sorted({match.upper() for match in CVE_RE.findall(text)})
        sas = sorted({match.upper() for match in SA_RE.findall(text)})
        for cve in cves:
            items.append({"cve_id": cve, "severity": severity, "description": _compact(text), "source_type": source_type, "source_url": source_url, "published_date": issue.get("created_at") or issue.get("updated_at") or ""})
        for sa in sas:
            items.append({"sa_id": sa, "is_sa": True, "severity": severity, "description": _compact(text), "source_type": source_type, "source_url": source_url, "published_date": issue.get("created_at") or issue.get("updated_at") or ""})
        if not cves and not sas and _is_security_issue(text, issue):
            items.append({"is_broad_sec": True, "severity": severity, "description": _compact(text), "source_type": source_type, "source_url": source_url, "published_date": issue.get("created_at") or issue.get("updated_at") or "", "matched_keywords": _matched_keywords(text)})
    return dedupe_security_items(items)


def extract_security_items_from_pull_requests(prs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return extract_security_items_from_issues(prs, source_type="project_pr")


def _is_security_issue(text: str, issue: dict[str, Any]) -> bool:
    lowered = text.lower()
    labels = " ".join(str(label.get("name") if isinstance(label, dict) else label) for label in issue.get("labels") or []).lower()
    return bool(CVE_RE.search(text) or broad_security_keywords(f"{lowered} {labels}"))


def _matched_keywords(text: str) -> list[str]:
    return broad_security_keywords(text)


def _compact(text: str, limit: int = 500) -> str:
    return " ".join((text or "").split())[:limit]
