from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.services import domain_items

DOMAIN = "threats"


def targets(conn: sqlite3.Connection, limit: int = 50) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="target", limit=limit)


def latest_artifact_preview(conn: sqlite3.Connection, artifact_type: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM artifacts WHERE artifact_type = ? ORDER BY id DESC LIMIT 1", (artifact_type,)).fetchone()
    if not row:
        return {"domain": DOMAIN, "artifact_type": artifact_type, "status": "missing", "items": []}
    artifact = repo.row_to_dict(row)
    data = _read_json_artifact(artifact.get("path", ""))
    return {"domain": DOMAIN, "artifact_type": artifact_type, "status": "ok", "artifact": artifact, "data": _preview_data(artifact_type, data)}


def _read_json_artifact(path: str) -> Any:
    try:
        artifact_path = Path(path)
        if not artifact_path.exists():
            return {}
        return json.loads(artifact_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _preview_data(artifact_type: str, data: Any) -> Any:
    if not isinstance(data, dict):
        return data
    if artifact_type == "huawei_cve_scout":
        orgs = data.get("orgs") or {}
        top_orgs = []
        for org, org_data in orgs.items():
            top_orgs.append({
                "org": org,
                "has_security_repo": org_data.get("has_security_repo", False),
                "security_repo_name": org_data.get("security_repo_name", ""),
                "projects_with_sec_data": org_data.get("projects_with_sec_data", 0),
                "total_projects": org_data.get("total_projects", 0),
            })
        top_orgs.sort(key=lambda item: item["projects_with_sec_data"], reverse=True)
        return {"meta": data.get("meta") or {}, "top_orgs": top_orgs[:20]}
    if artifact_type == "huawei_attack_surface":
        projects = data.get("projects") or []
        report = data.get("report") or {}
        top_projects = [
            {
                "name": item.get("name"),
                "url": item.get("url"),
                "description": item.get("description"),
                "attack_surface_score": item.get("attack_surface_score"),
                "grade": item.get("grade"),
                "primary_attack_surface": item.get("primary_attack_surface"),
                "score_breakdown": item.get("score_breakdown"),
                "filtered": item.get("filtered"),
                "deprioritized": item.get("deprioritized"),
            }
            for item in projects[:50]
        ]
        return {"report": report, "top_projects": top_projects}
    if artifact_type == "huawei_threat_report":
        return {
            "title": data.get("title"),
            "targets": data.get("targets"),
            "assets": data.get("assets"),
            "high_risk_targets": data.get("high_risk_targets", [])[:30],
            "cve_scout_report": data.get("cve_scout_report", {}),
            "attack_surface_report": data.get("attack_surface_report", {}),
        }
    return data
