from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.threats.security_repo_discovery import discover_security_repos, group_projects_by_org
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.registry import SourceRegistry

DEFAULT_LIVE_ORGS = [
    {"platform": "gitcode", "org": "Ascend"},
    {"platform": "gitcode", "org": "Cangjie"},
    {"platform": "gitcode", "org": "Cantian"},
    {"platform": "gitcode", "org": "DevCloudFE"},
    {"platform": "gitcode", "org": "ModelEngine"},
    {"platform": "gitcode", "org": "arkui-x"},
    {"platform": "gitcode", "org": "cann"},
    {"platform": "gitcode", "org": "eBackup"},
    {"platform": "gitcode", "org": "huaweicloud"},
    {"platform": "gitcode", "org": "kappital"},
    {"platform": "gitcode", "org": "kunpengcompute"},
    {"platform": "atomgit", "org": "mindspore"},
    {"platform": "gitcode", "org": "openFuyao"},
    {"platform": "gitcode", "org": "openHiTLS"},
    {"platform": "gitcode", "org": "openInula"},
    {"platform": "gitcode", "org": "openJiuwen"},
    {"platform": "gitcode", "org": "openUBMC"},
    {"platform": "atomgit", "org": "openeuler"},
    {"platform": "gitcode", "org": "opengauss"},
    {"platform": "gitcode", "org": "openharmony-sig"},
    {"platform": "gitcode", "org": "openharmony-tpc"},
    {"platform": "gitcode", "org": "openharmony"},
    {"platform": "gitcode", "org": "openkylin"},
    {"platform": "gitcode", "org": "openlookeng"},
    {"platform": "gitcode", "org": "opentiny"},
]
SECURITY_FILE_SUFFIXES = (".md", ".markdown", ".yml", ".yaml", ".json")
SECURITY_FILE_TERMS = ["security", "advisory", "cve", "vulnerability", "vuln", "漏洞", "安全公告", "安全披露"]


def load_huawei_sources(settings, params: dict[str, Any]) -> list[dict[str, Any]]:
    return load_huawei_live(params)


def load_huawei_live(params: dict[str, Any]) -> list[dict[str, Any]]:
    registry = SourceRegistry()
    repos = _collect_live_repos(registry, params)
    repos = _enrich_security_repos(registry, repos, params)
    assets = _collect_live_assets(registry, params)
    records = [{"source": "repos", "path": "connector:repos", "exists": True, "items": repos, "raw": {"projects": repos, "mode": "live"}, "mode": "live"}]
    records.extend(assets)
    return records


def _collect_live_repos(registry: SourceRegistry, params: dict[str, Any]) -> list[dict[str, Any]]:
    orgs = params.get("orgs") or DEFAULT_LIVE_ORGS
    page_limit = int(params.get("page_limit", 2))
    per_page = int(params.get("per_page", 100))
    repos: list[dict[str, Any]] = []
    for entry in orgs:
        if isinstance(entry, str):
            platform, org = _split_platform_org(entry)
        else:
            platform = str(entry.get("platform") or "gitcode")
            org = str(entry.get("org") or "")
        connector = registry.get(platform)
        for page in range(1, page_limit + 1):
            result = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{org}:repos", params={"resource": "repos", "org": org, "page": page, "per_page": per_page, "timeout_seconds": params.get("timeout_seconds", 20)}))
            if result.errors:
                break
            batch = [_normalize_repo_item(item, org=org, platform=platform) for item in result.items]
            repos.extend(batch)
            if len(batch) < per_page:
                break
    return repos


def _enrich_security_repos(registry: SourceRegistry, repos: list[dict[str, Any]], params: dict[str, Any]) -> list[dict[str, Any]]:
    if not repos or not params.get("fetch_security_details", True):
        return repos
    grouped = group_projects_by_org(repos)
    security = discover_security_repos(grouped)
    issue_pages = int(params.get("security_issue_pages", 1))
    max_files = int(params.get("security_file_limit", 8))
    max_security_repos = int(params.get("security_repo_limit", 8))
    by_key = {(repo.get("platform"), repo.get("org"), repo.get("name")): repo for repo in repos}
    for org, sec_data in security.items():
        for sec_repo in (sec_data.get("security_repos") or [])[:max_security_repos]:
            platform = sec_repo.get("platform") or _platform_from_url(sec_repo.get("url") or "")
            owner = sec_repo.get("org") or org
            repo_name = sec_repo.get("name") or ""
            connector = registry.get(platform) if platform else None
            if not connector or not repo_name:
                continue
            issues = []
            for page in range(1, issue_pages + 1):
                result = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{owner}/{repo_name}:issues", params={"resource": "issues", "owner": owner, "repo": repo_name, "page": page, "per_page": 100, "timeout_seconds": params.get("timeout_seconds", 20)}))
                if result.errors or not result.items:
                    break
                issues.extend(result.items)
                if len(result.items) < 100:
                    break
            security_files = _fetch_security_files(connector, platform, owner, repo_name, max_files=max_files)
            key = (platform, owner, repo_name)
            target = by_key.get(key) or sec_repo
            target["issues"] = issues
            target["security_files"] = security_files
    return repos


def _fetch_security_files(connector, platform: str, owner: str, repo_name: str, *, max_files: int) -> list[dict[str, Any]]:
    contents = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{owner}/{repo_name}:contents", params={"resource": "contents", "owner": owner, "repo": repo_name, "timeout_seconds": 15}))
    if contents.errors:
        return []
    candidates = []
    for item in contents.items:
        path = item.get("path") or item.get("name") or ""
        lowered = path.lower()
        if item.get("type") in {"dir", "tree"}:
            continue
        if not lowered.endswith(SECURITY_FILE_SUFFIXES):
            continue
        if not any(term.lower() in lowered for term in SECURITY_FILE_TERMS):
            continue
        candidates.append(path)
    files = []
    for path in candidates[:max_files]:
        result = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{owner}/{repo_name}:file", params={"resource": "file", "owner": owner, "repo": repo_name, "path": path, "timeout_seconds": 15}))
        if result.errors:
            continue
        files.append({"path": path, "content": result.raw_text, "source_url": f"{_web_base(platform)}/{owner}/{repo_name}/blob/master/{path}"})
    return files


def _collect_live_assets(registry: SourceRegistry, params: dict[str, Any]) -> list[dict[str, Any]]:
    if not params.get("include_assets", True):
        return []
    sources = [
        ("firmware", "hiascend", {"endpoint": "softwareCenter/queryResourceProductList", "lang": "zh", "type": "community"}),
        ("ascendhub", "hiascend", {"endpoint": "ascendHub/repositories/detail", "lang": "zh"}),
        ("mirrors", "huawei_mirror", {"catalog": params.get("mirror_catalog", "")}),
        ("openx_huawei", "openx_huawei", {}),
    ]
    records = []
    for source, connector_name, connector_params in sources:
        connector = registry.get(connector_name)
        result = connector.fetch(SourceFetchRequest(source_name=f"{connector_name}:{source}", params=connector_params))
        records.append({"source": source, "path": f"connector:{connector_name}", "exists": not bool(result.errors), "items": result.items, "raw": {"metadata": result.metadata, "errors": result.errors, "mode": "live"}, "mode": "live"})
    return records


def _split_platform_org(value: str) -> tuple[str, str]:
    if ":" in value:
        platform, org = value.split(":", 1)
        return platform, org
    return "gitcode", value


def _normalize_repo_item(item: dict[str, Any], *, org: str, platform: str) -> dict[str, Any]:
    owner = item.get("namespace", {}).get("path") if isinstance(item.get("namespace"), dict) else ""
    repo_org = item.get("org") or owner or org
    name = item.get("name") or item.get("path") or item.get("repo") or ""
    url = item.get("html_url") or item.get("web_url") or item.get("url") or (f"{_web_base(platform)}/{repo_org}/{name}" if name else "")
    return {"name": name, "url": url, "description": item.get("description") or item.get("desc") or "", "star_count": item.get("stargazers_count") or item.get("stars") or item.get("star_count") or 0, "org": repo_org, "platform": platform, "raw": item}


def _platform_from_url(url: str) -> str:
    if "atomgit.com" in (url or ""):
        return "atomgit"
    return "gitcode"


def _web_base(platform: str) -> str:
    return "https://atomgit.com" if platform == "atomgit" else "https://gitcode.com"
