from __future__ import annotations

from typing import Any


def resolve_candidate_links(items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    paper_keys = {str(item.get("external_id")): str(item.get("item_key")) for item in items if item.get("source_type") == "paper" and item.get("external_id")}
    project_keys = {str(item.get("repo_full_name")).lower(): str(item.get("item_key")) for item in items if item.get("source_type") == "project" and item.get("repo_full_name")}
    output: list[dict[str, Any]] = []
    link_count = 0
    for item in items:
        linked = set(str(value) for value in item.get("linked_item_keys") or [] if value)
        for paper_id in item.get("related_paper_ids") or []:
            if str(paper_id) in paper_keys:
                linked.add(paper_keys[str(paper_id)])
        for project_name in item.get("related_project_names") or []:
            if str(project_name).lower() in project_keys:
                linked.add(project_keys[str(project_name).lower()])
        linked.discard(str(item.get("item_key") or ""))
        link_count += len(linked)
        output.append({**item, "linked_item_keys": sorted(linked)})
    reverse: dict[str, set[str]] = {}
    for item in output:
        for linked_key in item.get("linked_item_keys") or []:
            reverse.setdefault(linked_key, set()).add(str(item.get("item_key")))
    resolved = [{**item, "linked_item_keys": sorted(set(item.get("linked_item_keys") or []) | reverse.get(str(item.get("item_key")), set()))} for item in output]
    return resolved, link_count
