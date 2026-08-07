from __future__ import annotations

import html
import re
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
        release_items = _release_manifest_items(issue, title=title, body=body, source_url=source_url)
        release_cves = {str(item.get("cve_id") or "") for item in release_items}
        items.extend(release_items)
        for cve in cves:
            if cve in release_cves:
                continue
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


def _release_manifest_items(issue: dict[str, Any], *, title: str, body: str, source_url: str) -> list[dict[str, Any]]:
    if "release" not in title.lower() or "<table" not in body.lower() or "仓库" not in body:
        return []
    items: list[dict[str, Any]] = []
    for row_html in re.findall(r"<tr\b[^>]*>(.*?)</tr>", body, re.I | re.S):
        cells = [_html_text(cell) for cell in re.findall(r"<td\b[^>]*>(.*?)</td>", row_html, re.I | re.S)]
        cves = sorted({match.upper() for match in CVE_RE.findall(row_html)})
        if not cves or len(cells) < 3:
            continue
        target_project = cells[2].strip()
        release_status = cells[3].strip() if len(cells) > 3 else ""
        cvss_score = _score(cells[4]) if len(cells) > 4 else None
        abi_changed = cells[5].strip() if len(cells) > 5 else ""
        issue_urls = re.findall(r"href\s*=\s*[\"']?([^\"'\s>]+)", row_html, re.I)
        evidence = " | ".join(cell for cell in cells if cell)
        for cve_id in cves:
            items.append(
                {
                    "cve_id": cve_id,
                    "severity": _severity_for_score(cvss_score),
                    "description": _compact(evidence),
                    "source_type": "release_manifest",
                    "source_url": source_url,
                    "published_date": issue.get("created_at") or issue.get("updated_at") or "",
                    "association_scope": "organization_coordination",
                    "target_project": target_project,
                    "release_status": release_status,
                    "cvss_score": cvss_score,
                    "abi_changed": abi_changed,
                    "release_name": title,
                    "target_issue_url": issue_urls[0] if issue_urls else "",
                }
            )
    return items


def _html_text(value: str) -> str:
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", value or "")).split())


def _score(value: str) -> float | None:
    match = re.search(r"\b(10(?:\.0)?|[0-9](?:\.\d)?)\b", value or "")
    return float(match.group(1)) if match else None


def _severity_for_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 9:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 4:
        return "medium"
    return "low"


def _compact(text: str, limit: int = 500) -> str:
    return " ".join((text or "").split())[:limit]
