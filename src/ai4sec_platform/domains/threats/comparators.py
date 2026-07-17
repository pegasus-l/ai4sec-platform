from __future__ import annotations

from typing import Any


def compare_cve_scout_outputs(old: dict[str, Any] | None, new: dict[str, Any]) -> dict[str, Any]:
    old = old or {}
    old_meta = old.get("meta") or {}
    new_meta = new.get("meta") or {}
    meta_fields = [
        "total_projects_in",
        "projects_with_sec_data",
        "total_cve_ids",
        "unique_cve_ids",
        "total_sa_ids",
        "unique_sa_ids",
        "total_broad_sec_items",
        "total_sec_items",
    ]
    meta_diff = {field: {"old": old_meta.get(field, 0), "new": new_meta.get(field, 0), "delta": (new_meta.get(field, 0) or 0) - (old_meta.get(field, 0) or 0)} for field in meta_fields}
    old_projects = _flatten_cve_projects(old)
    new_projects = _flatten_cve_projects(new)
    project_diffs = []
    for key in sorted(set(old_projects) | set(new_projects)):
        old_item = old_projects.get(key, {})
        new_item = new_projects.get(key, {})
        fields = ["cve_count", "sa_count", "broad_sec_count", "total_sec_items"]
        if any((old_item.get(field, 0) or 0) != (new_item.get(field, 0) or 0) for field in fields):
            project_diffs.append({"project": key, **{field: {"old": old_item.get(field, 0), "new": new_item.get(field, 0)} for field in fields}})
    return {"type": "cve_scout_compare", "meta_diff": meta_diff, "project_diff_count": len(project_diffs), "project_diffs_sample": project_diffs[:100]}


def compare_attack_surface_outputs(old: dict[str, Any] | None, new_projects: list[dict[str, Any]]) -> dict[str, Any]:
    old = old or {}
    old_projects = {item.get("name", ""): item for item in old.get("projects", []) if isinstance(item, dict)}
    new_by_name = {item.get("name", ""): item for item in new_projects if isinstance(item, dict)}
    diffs = []
    for name in sorted(set(old_projects) | set(new_by_name)):
        old_item = old_projects.get(name, {})
        new_item = new_by_name.get(name, {})
        old_score = old_item.get("attack_surface_score")
        new_score = new_item.get("attack_surface_score")
        old_grade = old_item.get("grade")
        new_grade = new_item.get("grade")
        old_filtered = old_item.get("filtered")
        new_filtered = new_item.get("filtered")
        if old_score != new_score or old_grade != new_grade or old_filtered != new_filtered:
            diffs.append({"name": name, "score": {"old": old_score, "new": new_score}, "grade": {"old": old_grade, "new": new_grade}, "filtered": {"old": old_filtered, "new": new_filtered}})
    return {"type": "attack_surface_compare", "old_count": len(old_projects), "new_count": len(new_by_name), "diff_count": len(diffs), "diffs_sample": diffs[:100]}


def _flatten_cve_projects(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for org, org_data in (data.get("orgs") or {}).items():
        for name, project in (org_data.get("projects") or {}).items():
            out[f"{org}/{name}"] = project if isinstance(project, dict) else {}
    return out
