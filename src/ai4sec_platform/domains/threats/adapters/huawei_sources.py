from __future__ import annotations

from pathlib import Path
from typing import Any

from ai4sec_platform.core.config import Settings
from ai4sec_platform.domains.threats.adapters.huawei_raw import load_huawei_raw
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.registry import SourceRegistry

DEFAULT_LIVE_ORGS = [
    {"platform": "gitcode", "org": "openharmony"},
    {"platform": "gitcode", "org": "openharmony-sig"},
    {"platform": "atomgit", "org": "openeuler"},
]


def load_huawei_sources(settings: Settings, params: dict[str, Any]) -> list[dict[str, Any]]:
    mode = str(params.get("mode") or "local_raw")
    if mode == "live":
        return load_huawei_live(params)
    root = Path(settings.legacy_sources.get("huawei_dir", ""))
    records = load_huawei_raw(root)
    for record in records:
        record["mode"] = "local_raw"
    return records


def load_huawei_live(params: dict[str, Any]) -> list[dict[str, Any]]:
    registry = SourceRegistry()
    repos = _collect_live_repos(registry, params)
    assets = _collect_live_assets(registry, params)
    records = [
        {"source": "repos", "path": "live:repos", "exists": True, "items": repos, "raw": {"projects": repos, "mode": "live"}, "mode": "live"},
        {"source": "scored_repos", "path": "live:scored_repos", "exists": True, "items": [], "raw": {"projects": [], "mode": "live"}, "mode": "live"},
        {"source": "repo_cves", "path": "live:repo_cves", "exists": True, "items": [], "raw": {"orgs": {}, "mode": "live"}, "mode": "live"},
    ]
    records.extend(assets)
    return records


def _collect_live_repos(registry: SourceRegistry, params: dict[str, Any]) -> list[dict[str, Any]]:
    orgs = params.get("orgs") or DEFAULT_LIVE_ORGS
    page_limit = int(params.get("page_limit", 1))
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
            result = connector.fetch(SourceFetchRequest(source_name=f"{platform}:{org}:repos", params={"resource": "repos", "org": org, "page": page, "per_page": per_page}))
            if result.errors:
                repos.append({"org": org, "platform": platform, "_fetch_errors": result.errors, "name": f"{org}:fetch_error", "url": "", "description": "", "star_count": 0})
                break
            batch = [_normalize_repo_item(item, org=org, platform=platform) for item in result.items]
            repos.extend(batch)
            if len(batch) < per_page:
                break
    return repos


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
        records.append({"source": source, "path": f"live:{connector_name}", "exists": not bool(result.errors), "items": result.items, "raw": {"metadata": result.metadata, "errors": result.errors, "mode": "live"}, "mode": "live"})
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
    url = item.get("html_url") or item.get("web_url") or item.get("url") or (f"https://{platform}.com/{repo_org}/{name}" if name else "")
    return {
        "name": name,
        "url": url,
        "description": item.get("description") or item.get("desc") or "",
        "star_count": item.get("stargazers_count") or item.get("stars") or item.get("star_count") or 0,
        "org": repo_org,
        "platform": platform,
        "raw": item,
    }
