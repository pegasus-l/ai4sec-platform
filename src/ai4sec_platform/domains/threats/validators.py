from __future__ import annotations

from typing import Any


def validate_repo_projects(projects: list[dict[str, Any]]) -> dict[str, Any]:
    required = {"name", "url", "description", "star_count"}
    missing_rows = []
    for index, project in enumerate(projects):
        missing = sorted(required - set(project.keys()))
        if missing:
            missing_rows.append({"index": index, "name": project.get("name", ""), "missing": missing})
    return {"status": "pass" if not missing_rows else "warn", "total": len(projects), "missing_rows": missing_rows[:50], "missing_count": len(missing_rows)}


def validate_cve_scout_output(data: dict[str, Any]) -> dict[str, Any]:
    meta = data.get("meta") or {}
    orgs = data.get("orgs") or {}
    issues = []
    if not orgs:
        issues.append("missing_orgs")
    if int(meta.get("total_projects_in") or 0) == 0:
        issues.append("zero_projects")
    for org, org_data in orgs.items():
        if "projects" not in org_data:
            issues.append(f"{org}:missing_projects")
    return {"status": "pass" if not issues else "warn", "issues": issues, "meta": meta}
