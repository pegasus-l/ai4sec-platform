from __future__ import annotations

from typing import Any


def build_cve_scout_report(data: dict[str, Any]) -> dict[str, Any]:
    meta = data.get("meta") or {}
    top_orgs = []
    for org, org_data in (data.get("orgs") or {}).items():
        top_orgs.append({"org": org, "projects_with_sec_data": org_data.get("projects_with_sec_data", 0), "total_projects": org_data.get("total_projects", 0), "has_security_repo": org_data.get("has_security_repo", False)})
    top_orgs.sort(key=lambda item: item["projects_with_sec_data"], reverse=True)
    return {
        "title": "华为开源项目 CVE 历史侦察报告",
        "summary": f"处理项目 {meta.get('total_projects_in', 0)} 个，发现有安全数据项目 {meta.get('projects_with_sec_data', 0)} 个，唯一 CVE {meta.get('unique_cve_ids', 0)} 个。",
        "metrics": meta,
        "top_orgs": top_orgs[:20],
    }


def build_attack_surface_report(scored_projects: list[dict[str, Any]]) -> dict[str, Any]:
    kept = [item for item in scored_projects if not item.get("filtered")]
    dropped = [item for item in scored_projects if item.get("filtered")]
    by_grade: dict[str, int] = {}
    for item in kept:
        grade = item.get("grade") or "unknown"
        by_grade[grade] = by_grade.get(grade, 0) + 1
    top = sorted(kept, key=lambda item: (-float(item.get("attack_surface_score") or 0), -int(item.get("star_count") or 0)))[:20]
    return {
        "title": "华为开源项目漏洞挖掘价值评估报告",
        "summary": f"总项目 {len(scored_projects)} 个，保留 {len(kept)} 个，过滤 {len(dropped)} 个，A/B 项目 {by_grade.get('A', 0) + by_grade.get('B', 0)} 个。",
        "by_grade": by_grade,
        "total_kept": len(kept),
        "total_dropped": len(dropped),
        "top_projects": top,
    }
