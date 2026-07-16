from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ai4sec_platform.core.ids import new_id
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.importers.common import clean_tags, file_summary, read_json, text_excerpt


def import_ai_for_sec(conn: sqlite3.Connection, raw_dir: Path, limit_news: int = 20, limit_capabilities: int = 12) -> dict[str, Any]:
    selected_path = raw_dir / "selected_entries.json"
    review_path = raw_dir / "review_history.json"
    selected = read_json(selected_path) if selected_path.exists() else {"entries": []}
    entries = selected.get("entries", []) if isinstance(selected, dict) else []
    entries = [item for item in entries if isinstance(item, dict)]
    entries.sort(key=lambda item: (item.get("score") or 0, item.get("date_reviewed") or ""), reverse=True)

    run_id = new_id("run_news_import")
    repo.create_pipeline_run(
        conn,
        run_id=run_id,
        domain="news",
        pipeline_name="import.ai_for_sec_selected_entries",
        source_path=str(selected_path),
        summary={"entry_count": len(entries), "imported_limit": limit_news},
    )
    repo.create_task_run(conn, run_id=run_id, step_name="read_selected_entries", metrics=file_summary(selected_path))
    repo.create_artifact(conn, run_id=run_id, artifact_type="legacy_selected_entries", path=str(selected_path), **_artifact_kwargs(selected_path))
    if review_path.exists():
        repo.create_artifact(conn, run_id=run_id, artifact_type="legacy_review_history", path=str(review_path), **_artifact_kwargs(review_path))

    imported_news = 0
    imported_capabilities = 0
    for entry in entries[:limit_news]:
        item_id = _create_news_item(conn, entry)
        imported_news += 1
        _create_review_evidence(conn, "news", item_id, entry)
        if (entry.get("score") or 0) >= 8:
            repo.create_human_queue_item(
                conn,
                domain="news",
                item_id=item_id,
                queue_type="featured_candidate",
                priority=1 if (entry.get("score") or 0) >= 9 else 2,
                reason="高分资讯候选，建议人工确认是否进入精选或专题。",
                payload={"legacy_id": entry.get("id"), "source": entry.get("source")},
            )

    capability_candidates = [item for item in entries if item.get("code_url") or item.get("type") == "repo" or item.get("has_code")]
    for entry in capability_candidates[:limit_capabilities]:
        item_id = _create_capability_item(conn, entry)
        imported_capabilities += 1
        _create_review_evidence(conn, "capabilities", item_id, entry)
        repo.create_human_queue_item(
            conn,
            domain="capabilities",
            item_id=item_id,
            queue_type="repro_candidate",
            priority=2,
            reason="来自 AI-for-Sec 高分条目，第一阶段仅展示待复现状态。",
            payload={"code_url": entry.get("code_url"), "legacy_id": entry.get("id")},
        )

    repo.create_data_source(conn, domain="news", name="AI-for-Sec selected_entries", source_type="legacy_json", latest_at=utc_now(), summary={"path": str(selected_path), "entries": len(entries)})
    repo.create_data_source(conn, domain="capabilities", name="AI-for-Sec high-code candidates", source_type="derived_legacy_json", latest_at=utc_now(), summary={"candidates": len(capability_candidates)})
    repo.create_quality_audit(conn, domain="news", audit_type="legacy_import", status="pass", score=1.0, summary=f"导入 AI-for-Sec 精选条目 {imported_news} 条。", details={"source": str(selected_path)})
    repo.create_quality_audit(conn, domain="capabilities", audit_type="repro_placeholder", status="warn", score=0.72, summary=f"生成能力候选 {imported_capabilities} 条，复现状态为占位。", details={"first_stage": True})
    repo.create_task_run(conn, run_id=run_id, step_name="build_news_and_capability_items", metrics={"news": imported_news, "capabilities": imported_capabilities})
    return {"news": imported_news, "capabilities": imported_capabilities, "source": str(selected_path)}


def _artifact_kwargs(path: Path) -> dict[str, Any]:
    summary = file_summary(path)
    return {"sha256": summary.get("sha256", ""), "bytes_size": int(summary.get("bytes", 0)), "payload_summary": summary}


def _create_news_item(conn: sqlite3.Connection, entry: dict[str, Any]) -> int:
    title = entry.get("title") or entry.get("id") or "未命名资讯"
    summary = entry.get("reason") or entry.get("abstract") or ""
    score = _safe_float(entry.get("score"))
    return repo.create_domain_item(
        conn,
        domain="news",
        item_type="report_item",
        title=title,
        summary=text_excerpt(summary, 520),
        score=score,
        status="featured" if (score or 0) >= 8 else "active",
        source=entry.get("source", "ai-for-sec"),
        source_url=entry.get("url") or entry.get("code_url") or "",
        primary_date=entry.get("published") or entry.get("date_reviewed") or entry.get("first_reviewed") or "",
        tags=clean_tags(entry.get("dimension"), entry.get("sub_category"), entry.get("categories"), entry.get("source")),
        metrics={"score": score, "has_code": bool(entry.get("has_code") or entry.get("code_url"))},
        payload={"legacy": entry, "authors": entry.get("authors", []), "code_url": entry.get("code_url")},
    )


def _create_capability_item(conn: sqlite3.Connection, entry: dict[str, Any]) -> int:
    title = entry.get("title") or entry.get("id") or "未命名能力候选"
    score = _safe_float(entry.get("score"))
    code_url = entry.get("code_url") or (entry.get("url") if entry.get("type") == "repo" else "")
    return repo.create_domain_item(
        conn,
        domain="capabilities",
        item_type="capability",
        title=title,
        summary=text_excerpt(entry.get("reason") or entry.get("abstract") or "", 520),
        score=score,
        status="待复现",
        source=entry.get("source", "ai-for-sec"),
        source_url=code_url or entry.get("url") or "",
        primary_date=entry.get("published") or entry.get("date_reviewed") or "",
        tags=clean_tags("AI-for-Sec", entry.get("dimension"), entry.get("sub_category"), "待复现"),
        metrics={"score": score, "repro_status": "pending", "has_code": bool(code_url)},
        payload={"legacy": entry, "code_url": code_url, "repro_status": "pending", "source_news_url": entry.get("url")},
    )


def _create_review_evidence(conn: sqlite3.Connection, domain: str, item_id: int, entry: dict[str, Any]) -> None:
    repo.create_evidence(
        conn,
        domain=domain,
        domain_item_id=item_id,
        evidence_type="review",
        title="旧 AI-for-Sec 审阅意见",
        content=entry.get("reason") or "",
        source_url=entry.get("url") or entry.get("code_url") or "",
        confidence=0.85,
        payload={"score": entry.get("score"), "dimension": entry.get("dimension"), "tech_points": entry.get("tech_points")},
    )


def _safe_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
