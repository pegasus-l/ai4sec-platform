from __future__ import annotations

import hashlib
from typing import Any


def normalize_huawei_item(source: str, item: dict[str, Any]) -> dict[str, Any]:
    if source in {"repos", "scored_repos"}:
        return normalize_repo(source, item)
    if source == "repo_cves":
        return normalize_cve_project(source, item)
    if source == "firmware":
        return normalize_firmware(source, item)
    return normalize_asset(source, item)


def normalize_repo(source: str, item: dict[str, Any]) -> dict[str, Any]:
    org = item.get("org") or _org_from_url(item.get("url", ""))
    name = item.get("name") or item.get("repo") or item.get("project") or "unknown"
    key = f"repo:{org}/{name}".lower()
    return {
        "item_key": key,
        "source": source,
        "source_type": "repo",
        "title": f"{org}/{name}" if org else name,
        "url": item.get("url") or "",
        "primary_date": item.get("updated_at") or item.get("created_at") or "",
        "summary": item.get("description") or item.get("reason") or "",
        "risk_score": item.get("attack_surface_score") or item.get("risk_score") or item.get("score"),
        "risk_grade": item.get("grade") or item.get("risk_grade") or "",
        "attack_surface": item.get("primary_attack_surface") or item.get("attack_surface") or "",
        "stars": item.get("stars") or item.get("star_count") or item.get("stargazers_count"),
        "cve_count": item.get("cve_count"),
        "raw": item,
    }


def normalize_cve_project(source: str, item: dict[str, Any]) -> dict[str, Any]:
    org = item.get("org") or _org_from_url(item.get("url", ""))
    name = item.get("name") or item.get("repo") or "unknown"
    cves = item.get("cves") or []
    key = f"repo-cves:{org}/{name}".lower()
    return {
        "item_key": key,
        "source": source,
        "source_type": "repo_cve",
        "title": f"{org}/{name} CVE 线索",
        "url": item.get("url") or "",
        "summary": f"CVE {len(cves)} 条，安全相关线索 {item.get('total_sec_items') or 0} 条。",
        "risk_score": item.get("cve_count") or len(cves),
        "cve_count": item.get("cve_count") or len(cves),
        "security_items": item.get("total_sec_items") or 0,
        "cves": cves,
        "raw": item,
    }


def normalize_firmware(source: str, item: dict[str, Any]) -> dict[str, Any]:
    model = item.get("productModel") or item.get("name") or "unknown"
    return {
        "item_key": f"firmware:{model}".lower(),
        "source": source,
        "source_type": "firmware",
        "title": model,
        "url": "",
        "summary": f"固件包 {item.get('packageCount') or 0} 个，最新发布 {item.get('latestRelease') or ''}。",
        "risk_score": item.get("packageCount") or 0,
        "raw": item,
    }


def normalize_asset(source: str, item: dict[str, Any]) -> dict[str, Any]:
    title = item.get("title") or item.get("name") or item.get("productModel") or source
    return {
        "item_key": f"asset:{source}:{hashlib.sha1(repr(item).encode('utf-8')).hexdigest()[:16]}",
        "source": source,
        "source_type": "asset",
        "title": title,
        "url": item.get("url") or item.get("href") or "",
        "summary": item.get("description") or item.get("summary") or "",
        "risk_score": None,
        "raw": item,
    }


def _org_from_url(value: str) -> str:
    parts = [part for part in (value or "").split("/") if part]
    if len(parts) >= 2:
        return parts[-2]
    return ""
