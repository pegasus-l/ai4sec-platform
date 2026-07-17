from __future__ import annotations

import re
from typing import Any

SECURITY_REPO_RE = re.compile(r"security|advisory|cve|vuln|cve-manager|cve-manage|security-committee", re.I)
PRIMARY_REPO_RE = re.compile(r"^(security|advisory|cve-manager|cve-manage-bot|security-committee)$", re.I)


def discover_security_repos(projects_by_org: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    discovered: dict[str, dict[str, Any]] = {}
    for org, projects in projects_by_org.items():
        candidates = []
        for project in projects:
            name = str(project.get("name") or "")
            url = str(project.get("url") or "")
            desc = str(project.get("description") or "")
            text = f"{name} {url} {desc}"
            if not SECURITY_REPO_RE.search(text):
                continue
            is_primary = bool(PRIMARY_REPO_RE.search(name))
            candidates.append({**project, "is_primary": is_primary, "discovery_reason": "primary_name" if is_primary else "security_keyword"})
        candidates.sort(key=lambda item: (not item["is_primary"], -int(item.get("star_count") or 0), item.get("name") or ""))
        discovered[org] = {
            "has_security_repo": bool(candidates),
            "primary_repo": candidates[0] if candidates else {},
            "security_repos": candidates,
            "security_repo_count": len(candidates),
        }
    return discovered


def group_projects_by_org(projects: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for project in projects:
        org = str(project.get("org") or _org_from_url(project.get("url") or "") or "unknown")
        grouped.setdefault(org, []).append(project)
    return grouped


def _org_from_url(url: str) -> str:
    parts = [part for part in str(url or "").split("/") if part]
    return parts[-2] if len(parts) >= 2 else ""
