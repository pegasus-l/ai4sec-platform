from __future__ import annotations

import sqlite3

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.threats.risk_scoring import score_threat_item


def build_threat_target(item: dict) -> dict:
    return {"item_type": "target", "title": item.get("title", "未命名目标"), "payload": item}


def build_threat_items(conn: sqlite3.Connection, items: list[dict], *, run_id: str) -> dict[str, int]:
    targets = 0
    evidence = 0
    for item in items:
        payload = repo.loads(item.get("normalized_json"), {}) if "normalized_json" in item else item
        item_type = "target" if payload.get("source_type") in {"repo", "repo_cve"} else "asset"
        scoring = score_threat_item(payload)
        payload = {**payload, "scoring": scoring.as_payload(), "vulnerability_signals": scoring.signals}
        domain_id = repo.create_domain_item(
            conn,
            domain="threats",
            item_type=item_type,
            title=payload.get("title") or "未命名威胁对象",
            summary=payload.get("summary") or "来自威胁 raw pipeline，待风险研判。",
            score=scoring.score,
            status="高风险待研判" if scoring.priority in {"critical", "high"} and item_type == "target" else "待研判" if item_type == "target" else "资产线索",
            source=payload.get("source") or "huawei_raw",
            source_url=payload.get("url") or "",
            primary_date=payload.get("primary_date") or "",
            tags=["raw_pipeline", payload.get("source_type") or "asset", scoring.grade, payload.get("risk_grade") or ""],
            metrics={"pipeline_run": run_id, "risk_score": scoring.score, "score_breakdown": scoring.breakdown},
            payload=payload,
        )
        targets += 1
        repo.create_evidence(
            conn,
            domain="threats",
            domain_item_id=domain_id,
            evidence_type="raw_threat_context",
            title="威胁 raw 证据",
            content=payload.get("summary") or "已关联本地 raw 威胁线索，CVE、固件、镜像和攻击面证据可继续增量增强。",
            source_url=payload.get("url") or "",
            confidence=min(1.0, scoring.score / 100),
            payload={"run_id": run_id, "item_key": item.get("item_key") or payload.get("item_key"), "scoring": scoring.as_payload()},
        )
        evidence += 1
        if scoring.score >= 80:
            repo.create_human_queue_item(
                conn,
                domain="threats",
                item_id=domain_id,
                queue_type="high_risk_target_review",
                priority=1,
                reason="Raw pipeline 识别到高风险目标，建议人工确认是否加入跟踪队列。",
                payload={"run_id": run_id, "item_key": payload.get("item_key")},
            )
    return {"items": targets, "evidence": evidence}


def _safe_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
