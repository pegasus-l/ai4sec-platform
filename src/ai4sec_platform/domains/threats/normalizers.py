from __future__ import annotations

import hashlib
from typing import Any


def normalize_huawei_item(source: str, item: dict[str, Any]) -> dict[str, Any]:
    if source == "repos":
        return normalize_repo(source, item)
    if source == "cve_findings":
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
    cve_count = item.get("cve_count") or len(cves)
    sa_count = item.get("sa_count") or len(item.get("sa_items") or [])
    broad_sec_count = item.get("broad_sec_count") or len(item.get("broad_sec_items") or [])
    total_sec_items = item.get("total_sec_items") or cve_count + sa_count + broad_sec_count
    key = f"repo-cves:{org}/{name}".lower()
    return {
        "item_key": key,
        "source": source,
        "source_type": "repo_cve",
        "title": _security_finding_title(org, name, cve_count=cve_count, sa_count=sa_count, broad_sec_count=broad_sec_count),
        "url": item.get("url") or "",
        "summary": _security_finding_summary(cve_count=cve_count, sa_count=sa_count, broad_sec_count=broad_sec_count, total_sec_items=total_sec_items),
        "risk_score": cve_count or sa_count or broad_sec_count,
        "cve_count": cve_count,
        "sa_count": sa_count,
        "broad_sec_count": broad_sec_count,
        "total_sec_items": total_sec_items,
        "scan_mode": item.get("scan_mode") or "",
        "security_items": item.get("total_sec_items") or 0,
        "cves": cves,
        "sa_items": item.get("sa_items") or [],
        "broad_sec_items": item.get("broad_sec_items") or [],
        "raw": item,
    }


def normalize_firmware(source: str, item: dict[str, Any]) -> dict[str, Any]:
    model = item.get("productModel") or item.get("modelName") or item.get("name") or item.get("productName") or "unknown"
    return {
        "item_key": f"firmware:{model}".lower(),
        "source": source,
        "source_type": "firmware",
        "title": model,
        "url": "",
        "summary": item.get("description") or item.get("softwareExplain") or f"固件/型号线索：{model}。",
        "risk_score": item.get("packageCount") or item.get("downloadCount") or 0,
        "raw": item,
    }


def normalize_asset(source: str, item: dict[str, Any]) -> dict[str, Any]:
    title = item.get("title") or item.get("displayName") or item.get("name") or item.get("repoName") or item.get("productModel") or source
    return {
        "item_key": f"asset:{source}:{hashlib.sha1(repr(item).encode('utf-8')).hexdigest()[:16]}",
        "source": source,
        "source_type": "asset",
        "title": title,
        "url": item.get("url") or item.get("href") or item.get("webUrl") or "",
        "summary": item.get("description") or item.get("summary") or item.get("msg") or item.get("source_type") or "",
        "risk_score": item.get("packageCount") or item.get("downloadCount"),
        "raw": item,
    }


def _org_from_url(value: str) -> str:
    parts = [part for part in (value or "").split("/") if part]
    if len(parts) >= 2:
        return parts[-2]
    return ""


def _security_finding_title(org: str, name: str, *, cve_count: int, sa_count: int, broad_sec_count: int) -> str:
    prefix = f"{org}/{name}" if org else name
    if cve_count:
        return f"{prefix} CVE 线索"
    if sa_count:
        return f"{prefix} 安全公告线索"
    if broad_sec_count:
        return f"{prefix} 安全 issue 线索"
    return f"{prefix} 攻击面线索"


def _security_finding_summary(*, cve_count: int, sa_count: int, broad_sec_count: int, total_sec_items: int) -> str:
    if total_sec_items:
        return f"CVE {cve_count} 条，安全公告 {sa_count} 条，安全 issue {broad_sec_count} 条。"
    return "未发现明确 CVE/SA，按攻击面和仓库特征保留为潜在威胁目标。"
