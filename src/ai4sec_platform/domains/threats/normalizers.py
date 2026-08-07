from __future__ import annotations

import hashlib
import json
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
    description = item.get("description") or item.get("reason") or ""
    return {
        "item_key": key,
        "source": source,
        "source_type": "repo",
        "title": f"{org}/{name}" if org else name,
        "org": org,
        "name": name,
        "url": item.get("url") or "",
        "primary_date": item.get("updated_at") or item.get("created_at") or "",
        "summary": description,
        "summary_original": description,
        "description_original": description,
        "summary_source": "repo_description" if description else "empty",
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
    coordination_cves = [cve for cve in cves if cve.get("association_scope") == "organization_coordination"]
    direct_cves = [cve for cve in cves if cve.get("association_scope") != "organization_coordination"]
    target_projects = sorted({str(cve.get("target_project")) for cve in coordination_cves if cve.get("target_project")})
    cve_count = item.get("cve_count") or len(cves)
    sa_count = item.get("sa_count") or len(item.get("sa_items") or [])
    broad_sec_count = item.get("broad_sec_count") or len(item.get("broad_sec_items") or [])
    total_sec_items = item.get("total_sec_items") or cve_count + sa_count + broad_sec_count
    key = f"repo:{org}/{name}".lower()
    security_summary = _security_finding_summary(cve_count=cve_count, sa_count=sa_count, broad_sec_count=broad_sec_count, total_sec_items=total_sec_items)
    return {
        "item_key": key,
        "source": source,
        "source_type": "repo_cve",
        "title": f"{org}/{name}" if org else name,
        "security_title": _security_finding_title(org, name, cve_count=cve_count, sa_count=sa_count, broad_sec_count=broad_sec_count),
        "org": org,
        "name": name,
        "url": item.get("url") or "",
        "summary": "",
        "security_summary": security_summary,
        "summary_source": "security_summary",
        "risk_score": len(direct_cves) or sa_count or broad_sec_count,
        "cve_count": cve_count,
        "sa_count": sa_count,
        "broad_sec_count": broad_sec_count,
        "total_sec_items": total_sec_items,
        "scan_mode": item.get("scan_mode") or "",
        "security_items": item.get("total_sec_items") or 0,
        "cves": cves,
        "direct_cve_count": len(direct_cves),
        "coordination_cve_count": len(coordination_cves),
        "coordination_summary": {
            "cve_count": len(coordination_cves),
            "target_projects": target_projects,
        },
        "sa_items": item.get("sa_items") or [],
        "broad_sec_items": item.get("broad_sec_items") or [],
        "raw": item,
    }


def normalize_firmware(source: str, item: dict[str, Any]) -> dict[str, Any]:
    model = item.get("productModel") or item.get("modelName") or item.get("name") or item.get("productModel") or "unknown"
    fw_type = item.get("source_type", "community")
    result = {
        "item_key": f"firmware:{model}:{fw_type}".lower(),
        "source": source,
        "source_type": f"firmware_{fw_type}",
        "title": model,
        "url": item.get("downloadUrl") or "",
        "summary": item.get("softwareExplain") or item.get("description") or f"固件/型号线索：{model}。",
        "risk_score": item.get("packageCount") or item.get("downloadCount") or 0,
        "raw": item,
    }
    # Package-level fields from 3-level API query
    if item.get("packageName"):
        result["package_name"] = item["packageName"]
        result["file_size"] = item.get("fileSize", "")
        result["release_time"] = item.get("releaseTime", "")
        result["software_explain"] = item.get("softwareExplain", "")
        result["download_url"] = item.get("downloadUrl", "")
        result["product_type"] = item.get("productType", "")
        result["firmware_version"] = item.get("firmwareVersion", "")
        result["product_series"] = item.get("productSeries", "")
        result["firmware_origin"] = fw_type  # community or commercial
    return result


import re
from typing import Any


def _determine_file_type(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    type_map = {
        "bin": "firmware_bin", "cc": "system_software_cc", "pat": "patch_file",
        "zip": "compressed_archive", "efs": "efs_patch", "dat": "license_dat",
    }
    return type_map.get(ext, f"other_{ext}" if ext else "unknown")


def _parse_filename_metadata(filename: str) -> tuple[str, str, str]:
    """Extract device_model, software_version, version_variant from firmware filename."""
    device_model = ""
    software_version = ""
    version_variant = ""
    name_without_ext = filename.rsplit(".", 1)[0] if "." in filename else filename

    m = re.match(r'^([A-Za-z0-9][A-Za-z0-9\-]+?)_V(\d+R\d+[A-Za-z0-9]*?)(?:_|$)', name_without_ext)
    if not m:
        m = re.match(r'^([A-Za-z0-9][A-Za-z0-9\-]+?)-V(\d+R\d+[A-Za-z0-9]*?)(?:_|-|$)', name_without_ext)
    if m:
        device_model = m.group(1)
        software_version = "V" + m.group(2)
        rest = name_without_ext[m.end():]
        if rest.startswith(("_", "-")):
            rest = rest[1:]
        version_variant = rest
        return device_model, software_version, version_variant

    m = re.match(r'^V(\d+R\d+[A-Za-z0-9]*)', name_without_ext)
    if m:
        software_version = "V" + m.group(1)
        rest = name_without_ext[len(software_version):]
        if rest.startswith("_"):
            rest = rest[1:]
        version_variant = rest
        return device_model, software_version, version_variant

    ver_pos = re.search(r'V\d+R\d+', name_without_ext)
    if ver_pos:
        prefix = name_without_ext[:ver_pos.start()]
        ver_match = re.match(r'V(\d+R\d+[A-Za-z0-9]*)', name_without_ext[ver_pos.start():])
        if ver_match:
            device_model = prefix
            software_version = "V" + ver_match.group(1)
            after_ver = name_without_ext[ver_pos.start() + len(software_version):]
            if after_ver.startswith(("_", "-")):
                after_ver = after_ver[1:]
            version_variant = after_ver
            return device_model, software_version, version_variant

    return device_model, software_version, version_variant


def normalize_asset(source: str, item: dict[str, Any]) -> dict[str, Any]:
    title = item.get("title") or item.get("displayName") or item.get("name") or item.get("hub_name") or item.get("filename") or item.get("repoName") or item.get("productModel") or source
    identity = _asset_identity(source, item)
    result = {
        "item_key": f"asset:{source}:{hashlib.sha1(identity.encode('utf-8')).hexdigest()[:20]}",
        "source": source,
        "source_type": "asset",
        "title": title,
        "url": item.get("url") or item.get("href") or item.get("webUrl") or "",
        "summary": item.get("description") or item.get("summary") or item.get("msg") or item.get("source_type") or "",
        "risk_score": item.get("packageCount") or item.get("downloadCount"),
        "raw": item,
    }
    if source == "openx_huawei":
        filename = item.get("name") or item.get("filename") or ""
        device_model, software_version, version_variant = _parse_filename_metadata(filename)
        result["device_model"] = device_model
        result["software_version"] = software_version
        result["version_variant"] = version_variant
        result["file_type"] = _determine_file_type(filename)
        if device_model:
            result["title"] = device_model
    if source == "mirrors":
        catalog = item.get("catalog", [])
        if isinstance(catalog, list) and catalog:
            result["os"] = _infer_os_from_catalog(catalog, item.get("msg", ""))
            result["category_display"] = ", ".join(catalog)
    if source == "ascendhub":
        # Tags response items have tags.list with version tags — extract them
        tags_obj = item.get("tags")
        if isinstance(tags_obj, dict) and isinstance(tags_obj.get("list"), list):
            version_tags = []
            for tag_item in tags_obj["list"]:
                if isinstance(tag_item, dict):
                    version_tags.append({
                        "tag": tag_item.get("tag", ""),
                        "size": tag_item.get("size", ""),
                        "update_time": tag_item.get("updateTime", ""),
                        "architectures": tag_item.get("architectures", []),
                    })
            result["version_tags"] = version_tags
            result["hub_id"] = item.get("hub_id", "")
            result["hub_name"] = item.get("hub_name", "")
            if item.get("hub_name"):
                result["title"] = item["hub_name"]
            result["source_type"] = "ascendhub_version_tags"
        else:
            # Detail response — add hub_id for frontend merging
            result["hub_id"] = item.get("hub_id", "")
    return result


def _asset_identity(source: str, item: dict[str, Any]) -> str:
    if source == "firmware":
        fields = [item.get("productTypes"), item.get("productSeries"), item.get("productModel"), item.get("source_type")]
    elif source == "ascendhub":
        fields = [item.get("hub_id"), item.get("hub_name"), item.get("name")]
    elif source == "mirrors":
        fields = [item.get("mirrorPath"), item.get("name"), item.get("url")]
    elif source == "openx_huawei":
        fields = [item.get("download_url"), item.get("filename"), item.get("name")]
    else:
        fields = [item.get("id"), item.get("url"), item.get("name"), item.get("title"), item.get("productModel")]
    if any(value not in (None, "", [], {}) for value in fields):
        return json.dumps(fields, ensure_ascii=False, sort_keys=True, default=str)
    return json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)


def _infer_os_from_catalog(catalog: list[str], msg: str = "") -> str:
    """Infer OS from catalog tags (like old huawei_mirror_scraper.py)."""
    if "os" in catalog:
        return msg or "Linux/Unix"
    if "language" in catalog:
        return "跨平台"
    if "docker" in catalog:
        return "容器"
    if "tool" in catalog:
        return "跨平台"
    if "sdk" in catalog:
        return "跨平台"
    if "huawei" in catalog:
        return "华为专属"
    if "ascend" in catalog:
        return "昇腾"
    if "x86" in catalog:
        return "x86_64"
    if "arm" in catalog:
        return "ARM"
    return ""


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
