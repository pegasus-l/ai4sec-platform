from __future__ import annotations

import json
from pathlib import Path
from typing import Any

RAW_FILES = {
    "repos": "data/huawei_repos.json",
    "scored_repos": "data/huawei_repos_scored.json",
    "repo_cves": "data/huawei_repos_cves.json",
    "firmware": "data/firmware_aggregated.json",
    "ascendhub": "data/ascendhub_aggregated.json",
    "mirrors": "data/huawei_opensource_mirrors.json",
}


def load_huawei_raw(root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for source, rel in RAW_FILES.items():
        path = root / rel
        if not path.exists():
            records.append({"source": source, "path": str(path), "exists": False, "items": [], "raw": None})
            continue
        raw = _read_json(path)
        records.append({"source": source, "path": str(path), "exists": True, "items": extract_items(source, raw), "raw": raw})
    return records


def extract_items(source: str, raw: Any) -> list[dict[str, Any]]:
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if not isinstance(raw, dict):
        return []
    if source in {"repos", "scored_repos"}:
        return [item for item in raw.get("projects", []) if isinstance(item, dict)]
    if source == "repo_cves":
        items: list[dict[str, Any]] = []
        orgs = raw.get("orgs", {})
        if isinstance(orgs, dict):
            for org, org_data in orgs.items():
                projects = org_data.get("projects", {}) if isinstance(org_data, dict) else {}
                for name, project in projects.items():
                    if isinstance(project, dict):
                        items.append({"org": org, "name": name, **project})
        return items
    for key in ["items", "results", "projects", "data"]:
        value = raw.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
