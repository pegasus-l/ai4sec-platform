from __future__ import annotations

from collections import Counter
import re
from typing import Any

from ai4sec_platform.domains.threats.issue_extractors import extract_security_items_from_issues, extract_security_items_from_pull_requests
from ai4sec_platform.domains.threats.security_file_parsers import dedupe_security_items, parse_security_file, parse_security_json
from ai4sec_platform.domains.threats.security_repo_discovery import discover_security_repos, group_projects_by_org

STAR_SCAN_THRESHOLD = 10


def build_cve_scout_from_local_records(
    projects: list[dict[str, Any]],
    existing_cve_orgs: dict[str, Any] | None = None,
    org_security_materials: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    grouped = group_projects_by_org(projects)
    security = discover_security_repos(grouped)
    materials_by_org = _group_org_security_materials(org_security_materials or [])
    orgs_output: dict[str, Any] = {}
    source_stats: Counter[str] = Counter()
    scan_mode_stats: Counter[str] = Counter()
    total_projects_with_data = 0
    total_cve = 0
    total_sa = 0
    total_broad = 0
    existing_cve_orgs = existing_cve_orgs or {}
    for org, org_projects in grouped.items():
        existing_projects = ((existing_cve_orgs.get(org) or {}).get("projects") or {}) if isinstance(existing_cve_orgs.get(org), dict) else {}
        org_data = {
            "has_security_repo": bool(security.get(org, {}).get("has_security_repo")),
            "security_repo_name": (security.get(org, {}).get("primary_repo") or {}).get("name", ""),
            "security_repo_url": (security.get(org, {}).get("primary_repo") or {}).get("url", ""),
            "total_projects": len(org_projects),
            "projects": {},
        }
        org_projects_with_data = 0
        org_materials = materials_by_org.get(org, [])
        security_pool = _security_pool_from_existing(existing_projects)
        security_pool.extend(_security_pool_from_org_materials(org_materials, org_projects))
        security_pool.extend(_security_pool_from_connector_materials(org_projects, include_security_repo_projects=not bool(org_materials)))
        security_pool = dedupe_security_items(security_pool)
        for project in org_projects:
            name = str(project.get("name") or "")
            existing = existing_projects.get(name) if isinstance(existing_projects, dict) else None
            if isinstance(existing, dict):
                pdata = _normalize_existing_project_cve(project, existing)
                scan_mode = pdata.get("scan_mode") or "from_existing"
            else:
                project_items = _project_local_security_items(project)
                pool_items = _match_pool(name, security_pool)
                fallback_items = []
                scan_mode = "from_pool" if pool_items else "not_scanned"
                if project_items:
                    scan_mode = "scanned_local_materials"
                if not pool_items and not project_items and int(project.get("star_count") or 0) >= STAR_SCAN_THRESHOLD:
                    fallback_items = extract_security_items_from_issues(project.get("issues") or [], source_type="project_issue")
                    fallback_items.extend(extract_security_items_from_pull_requests(project.get("pull_requests") or project.get("prs") or []))
                    scan_mode = "scanned_local_issues" if fallback_items else "scanned_no_hits"
                pdata = _project_cve_payload(project, dedupe_security_items([*project_items, *pool_items, *fallback_items]), scan_mode)
            org_data["projects"][name] = pdata
            scan_mode_stats[pdata.get("scan_mode", "unknown")] += 1
            for item in [*pdata.get("cves", []), *pdata.get("sa_items", []), *pdata.get("broad_sec_items", [])]:
                source_stats[item.get("source_type", "unknown")] += 1
            total_cve += pdata.get("cve_count", 0)
            total_sa += pdata.get("sa_count", 0)
            total_broad += pdata.get("broad_sec_count", 0)
            if pdata.get("total_sec_items", 0):
                org_projects_with_data += 1
                total_projects_with_data += 1
        org_data["projects_with_sec_data"] = org_projects_with_data
        orgs_output[org] = org_data
    unique_cves = sorted({item.get("cve_id") for org in orgs_output.values() for project in org["projects"].values() for item in project.get("cves", []) if item.get("cve_id")})
    unique_sas = sorted({item.get("sa_id") for org in orgs_output.values() for project in org["projects"].values() for item in project.get("sa_items", []) if item.get("sa_id")})
    return {
        "meta": {
            "total_projects_in": len(projects),
            "total_orgs": len(grouped),
            "projects_with_sec_data": total_projects_with_data,
            "total_cve_ids": total_cve,
            "unique_cve_ids": len(unique_cves),
            "total_sa_ids": total_sa,
            "unique_sa_ids": len(unique_sas),
            "total_broad_sec_items": total_broad,
            "total_sec_items": total_cve + total_sa + total_broad,
            "source_stats": dict(source_stats),
            "scan_mode_stats": dict(scan_mode_stats),
            "org_security_materials": sum(len(items) for items in materials_by_org.values()),
            "orgs_with_security_repo": sorted([org for org, data in security.items() if data.get("has_security_repo")]),
            "orgs_without_security_repo": sorted([org for org, data in security.items() if not data.get("has_security_repo")]),
            "star_scan_threshold": STAR_SCAN_THRESHOLD,
        },
        "security_repo_discovery": security,
        "orgs": orgs_output,
    }


def parse_security_repo_materials(materials: list[dict[str, Any]], repo_names: list[str] | None = None) -> list[dict[str, Any]]:
    parsed: list[dict[str, Any]] = []
    for material in materials:
        if not isinstance(material, dict):
            continue
        content = material.get("content") or material.get("text") or material.get("body") or ""
        source_path = material.get("path") or material.get("source_path") or ""
        source_url = material.get("url") or material.get("source_url") or ""
        if material.get("raw_json") is not None:
            items = parse_security_json(material.get("raw_json"), source_path=source_path, source_url=source_url, repo_names=repo_names)
        else:
            items = parse_security_file(str(content), source_path=source_path, source_url=source_url, repo_names=repo_names)
        parsed.extend(_with_material_metadata(items, material))
    return dedupe_security_items(parsed)


def _group_org_security_materials(materials: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for material in materials or []:
        if not isinstance(material, dict):
            continue
        org = str(material.get("org") or material.get("owner") or "unknown")
        grouped.setdefault(org, []).append(material)
    return grouped


def _security_pool_from_org_materials(materials: list[dict[str, Any]], projects: list[dict[str, Any]]) -> list[dict[str, Any]]:
    repo_names = [str(project.get("name") or "") for project in projects if project.get("name")]
    pool: list[dict[str, Any]] = []
    for material in materials or []:
        material_type = str(material.get("material_type") or material.get("source_type") or "")
        if material_type in {"security_repo_issue", "issue"}:
            pool.extend(_with_material_metadata(extract_security_items_from_issues([material], source_type="security_repo_issue"), material))
            continue
        if material_type in {"security_repo_pr", "pull_request", "pr"}:
            pool.extend(_with_material_metadata(extract_security_items_from_issues([material], source_type="security_repo_pr"), material))
            continue
        pool.extend(parse_security_repo_materials([material], repo_names=repo_names))
    return dedupe_security_items(pool)


def _with_material_metadata(items: list[dict[str, Any]], material: dict[str, Any]) -> list[dict[str, Any]]:
    enriched = []
    for item in items:
        enriched.append(
            {
                **item,
                "source_org": item.get("source_org") or material.get("org") or material.get("owner") or "",
                "source_security_repo": item.get("source_security_repo") or material.get("repo") or material.get("repo_name") or "",
                "source_platform": item.get("source_platform") or material.get("platform") or "",
                "project_hints": sorted({
                    *[str(value) for value in item.get("project_hints") or [] if value],
                    *([_project_from_issue_url(str(item.get("source_url") or ""))] if _project_from_issue_url(str(item.get("source_url") or "")) else []),
                }),
            }
        )
    return enriched


def _security_pool_from_existing(projects: dict[str, Any]) -> list[dict[str, Any]]:
    pool: list[dict[str, Any]] = []
    for name, pdata in (projects or {}).items():
        if not isinstance(pdata, dict):
            continue
        for key in ["cves", "sa_items", "broad_sec_items"]:
            for item in pdata.get(key) or []:
                if isinstance(item, dict):
                    pool.append({**item, "project_hints": list(set([name, *item.get("project_hints", [])]))})
    return pool


def _security_pool_from_connector_materials(projects: list[dict[str, Any]], *, include_security_repo_projects: bool = True) -> list[dict[str, Any]]:
    repo_names = [str(project.get("name") or "") for project in projects if project.get("name")]
    pool: list[dict[str, Any]] = []
    seen_material_ids: set[int] = set()
    for project in projects:
        if not _is_security_repo_project(project):
            for material in project.get("org_security_materials") or []:
                if not isinstance(material, dict):
                    continue
                material_id = id(material)
                if material_id in seen_material_ids:
                    continue
                seen_material_ids.add(material_id)
                pool.extend(parse_security_repo_materials([material], repo_names=repo_names))
            continue
        if not include_security_repo_projects:
            continue
        metadata = _project_security_material_metadata(project)
        for material in project.get("security_files") or []:
            if isinstance(material, dict):
                pool.extend(parse_security_repo_materials([{**material, **metadata}], repo_names=repo_names))
        pool.extend(_with_material_metadata(extract_security_items_from_issues(project.get("issues") or [], source_type="security_repo_issue"), metadata))
        pool.extend(_with_material_metadata(extract_security_items_from_issues(project.get("pull_requests") or project.get("prs") or [], source_type="security_repo_pr"), {**metadata, "material_type": "security_repo_pr"}))
        for material in project.get("org_security_materials") or []:
            if not isinstance(material, dict):
                continue
            material_id = id(material)
            if material_id in seen_material_ids:
                continue
            seen_material_ids.add(material_id)
            pool.extend(parse_security_repo_materials([{**material, **metadata}], repo_names=repo_names))
    return dedupe_security_items(pool)


def _project_security_material_metadata(project: dict[str, Any]) -> dict[str, Any]:
    return {
        "platform": project.get("platform") or "",
        "org": project.get("org") or "",
        "repo": project.get("name") or project.get("repo") or "",
    }


def _project_local_security_items(project: dict[str, Any]) -> list[dict[str, Any]]:
    if _is_security_repo_project(project):
        return []
    repo_names = [str(project.get("name") or "")]
    items: list[dict[str, Any]] = []
    items.extend(parse_security_repo_materials(project.get("security_files") or [], repo_names=repo_names))
    items.extend(extract_security_items_from_issues(project.get("issues") or [], source_type="project_issue"))
    items.extend(extract_security_items_from_pull_requests(project.get("pull_requests") or project.get("prs") or []))
    return dedupe_security_items(items)


def _is_security_repo_project(project: dict[str, Any]) -> bool:
    name = str(project.get("name") or "").lower()
    return bool(project.get("is_security_repo") or name in {"security", "advisory", "cve-manager", "cve-ease"} or any(token in name for token in ["security", "advisory", "cve", "vuln", "漏洞", "安全"]))


def _match_pool(project_name: str, pool: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lowered = project_name.lower()
    matched = []
    for item in pool:
        hints = [str(hint).lower() for hint in item.get("project_hints") or []]
        description = str(item.get("description") or "").lower()
        source_repos = [str(item.get("source_repo") or "").lower(), *[str(value).lower() for value in item.get("source_repos") or []]]
        has_explicit_hints = bool(hints or any(source_repos))
        if lowered in hints or any(_source_repo_matches(lowered, source_repo) for source_repo in source_repos) or (not has_explicit_hints and lowered and lowered in description):
            matched.append(item)
    return dedupe_security_items(matched)


def _source_repo_matches(project_name: str, source_repo: str) -> bool:
    if not project_name or not source_repo:
        return False
    normalized_source = source_repo.replace("/", " ").replace("|", " ").strip()
    return project_name == normalized_source or project_name in normalized_source.split() or project_name in normalized_source


def _project_from_issue_url(source_url: str) -> str:
    match = re.search(r"/(?:repos/)?[^/]+/([^/]+)/(?:issues|pull_requests)/", source_url or "", re.I)
    return match.group(1) if match else ""


def _normalize_existing_project_cve(project: dict[str, Any], existing: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": existing.get("url") or project.get("url") or "",
        "star_count": existing.get("star_count") if existing.get("star_count") is not None else project.get("star_count", 0),
        "scan_mode": existing.get("scan_mode") or "from_existing",
        "cve_count": int(existing.get("cve_count") or len(existing.get("cves") or [])),
        "sa_count": int(existing.get("sa_count") or len(existing.get("sa_items") or [])),
        "broad_sec_count": int(existing.get("broad_sec_count") or len(existing.get("broad_sec_items") or [])),
        "total_sec_items": int(existing.get("total_sec_items") or 0) or len(existing.get("cves") or []) + len(existing.get("sa_items") or []) + len(existing.get("broad_sec_items") or []),
        "cves": existing.get("cves") or [],
        "sa_items": existing.get("sa_items") or [],
        "broad_sec_items": existing.get("broad_sec_items") or [],
    }


def _project_cve_payload(project: dict[str, Any], items: list[dict[str, Any]], scan_mode: str) -> dict[str, Any]:
    cves = [item for item in items if item.get("cve_id")]
    sas = [item for item in items if item.get("sa_id") or item.get("is_sa")]
    broad = [item for item in items if not item.get("cve_id") and not item.get("sa_id")]
    return {
        "url": project.get("url") or "",
        "star_count": project.get("star_count") or 0,
        "scan_mode": scan_mode,
        "cve_count": len(cves),
        "sa_count": len(sas),
        "broad_sec_count": len(broad),
        "total_sec_items": len(items),
        "cves": cves,
        "sa_items": sas,
        "broad_sec_items": broad,
    }
