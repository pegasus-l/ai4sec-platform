from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ai4sec_platform.core.ids import new_id
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.importers.common import clean_tags, file_summary, read_json, text_excerpt


def import_huawei(conn: sqlite3.Connection, huawei_dir: Path, limit: int = 20) -> dict[str, Any]:
    scored_path = huawei_dir / "data" / "huawei_repos_scored.json"
    repos_path = huawei_dir / "data" / "huawei_repos.json"
    firmware_path = huawei_dir / "data" / "firmware_aggregated.json"
    mirror_path = huawei_dir / "data" / "huawei_opensource_mirrors.json"
    data = read_json(scored_path) if scored_path.exists() else read_json(repos_path)
    projects = data.get("projects", []) if isinstance(data, dict) else []
    projects = [item for item in projects if isinstance(item, dict)]
    projects.sort(key=lambda item: (item.get("attack_surface_score") or 0, item.get("star_count") or 0), reverse=True)

    run_id = new_id("run_threat_import")
    repo.create_pipeline_run(conn, run_id=run_id, domain="threats", pipeline_name="import.huawei_targets", source_path=str(scored_path if scored_path.exists() else repos_path), summary={"project_count": len(projects), "imported_limit": limit})
    repo.create_task_run(conn, run_id=run_id, step_name="read_huawei_repo_scores", metrics=file_summary(scored_path if scored_path.exists() else repos_path))
    for path, artifact_type in [(scored_path, "huawei_repo_scores"), (firmware_path, "huawei_firmware"), (mirror_path, "huawei_mirrors")]:
        if path.exists():
            summary = file_summary(path)
            repo.create_artifact(conn, run_id=run_id, artifact_type=artifact_type, path=str(path), sha256=summary.get("sha256", ""), bytes_size=int(summary.get("bytes", 0)), payload_summary=summary)

    imported = 0
    for project in projects[:limit]:
        item_id = _create_threat_target(conn, project)
        imported += 1
        _create_target_evidence(conn, item_id, project)
        if (project.get("attack_surface_score") or 0) >= 80:
            repo.create_human_queue_item(conn, domain="threats", item_id=item_id, queue_type="high_risk_target_review", priority=1, reason="高攻击面评分目标，建议人工确认是否加入跟踪队列。", payload={"url": project.get("url"), "grade": project.get("grade")})

    repo.create_data_source(conn, domain="threats", name="Huawei repo scored metadata", source_type="legacy_json", latest_at=utc_now(), summary={"path": str(scored_path), "projects": len(projects)})
    if firmware_path.exists():
        firmware = read_json(firmware_path)
        repo.create_data_source(conn, domain="threats", name="Huawei firmware aggregated", source_type="legacy_json", latest_at=utc_now(), summary={"path": str(firmware_path), "items": len(firmware) if isinstance(firmware, list) else 0})
    if mirror_path.exists():
        mirrors = read_json(mirror_path)
        repo.create_data_source(conn, domain="threats", name="Huawei open source mirrors", source_type="legacy_json", latest_at=utc_now(), summary={"path": str(mirror_path), "items": len(mirrors) if isinstance(mirrors, list) else 0})
    repo.create_quality_audit(conn, domain="threats", audit_type="legacy_target_import", status="pass", score=0.86, summary=f"导入华为威胁目标 {imported} 个，优先展示高攻击面评分项目。", details={"source": str(scored_path)})
    repo.create_task_run(conn, run_id=run_id, step_name="build_threat_targets", metrics={"targets": imported})
    return {"threats": imported, "source": str(scored_path)}


def _create_threat_target(conn: sqlite3.Connection, project: dict[str, Any]) -> int:
    score = _safe_float(project.get("attack_surface_score"))
    name = project.get("name") or project.get("displayName") or "未命名目标"
    surface = project.get("primary_attack_surface") or "unknown"
    grade = project.get("grade") or ""
    return repo.create_domain_item(
        conn,
        domain="threats",
        item_type="target",
        title=f"{project.get('org', 'Huawei')} / {name}",
        summary=text_excerpt(project.get("description") or f"攻击面：{surface}，评分：{score or 0}"),
        score=score,
        status="待研判" if (score or 0) >= 80 else "active",
        source="huawei-repo",
        source_url=project.get("url") or "",
        primary_date=project.get("updated_at") or "",
        tags=clean_tags(project.get("org"), surface, grade, "开源目标"),
        metrics={"attack_surface_score": score, "stars": project.get("star_count", 0), "grade": grade},
        payload={"legacy": project, "risk_grade": grade, "score_breakdown": project.get("score_breakdown", {})},
    )


def _create_target_evidence(conn: sqlite3.Connection, item_id: int, project: dict[str, Any]) -> None:
    breakdown = project.get("score_breakdown") or {}
    details = "；".join(f"{key}: {value}" for key, value in breakdown.items()) if isinstance(breakdown, dict) else ""
    repo.create_evidence(conn, domain="threats", domain_item_id=item_id, evidence_type="risk_score", title="攻击面评分证据", content=details or project.get("description") or "", source_url=project.get("url") or "", confidence=0.8, payload={"score_breakdown": breakdown, "primary_attack_surface": project.get("primary_attack_surface")})


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
