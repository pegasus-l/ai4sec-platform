from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.threats.repo_summary_enrichment import enrich_repo_summary
from ai4sec_platform.domains.threats.risk_scoring import score_threat_item


def build_threat_target(item: dict) -> dict:
    return {"item_type": "target", "title": item.get("title", "未命名目标"), "payload": item}


def build_threat_items(
    conn: sqlite3.Connection,
    items: list[dict],
    *,
    run_id: str,
    enrich_repo_summaries: bool = False,
    repo_summary_limit: int = 0,
    repo_summary_cache_dir: Path | None = None,
) -> dict[str, int]:
    targets = 0
    evidence = 0
    enriched_summaries = 0
    payloads = _merge_canonical_payloads(items)
    scored_payloads = []
    for payload in payloads:
        item_type = "target" if payload.get("source_type") in {"repo", "repo_cve"} else "asset"
        scoring = score_threat_item(payload)
        scored_payloads.append((payload, item_type, scoring))
    enriched_keys = _summary_enrichment_keys(scored_payloads, repo_summary_limit) if enrich_repo_summaries else set()
    for payload, item_type, scoring in scored_payloads:
        if payload.get("item_key") in enriched_keys:
            enrichment = enrich_repo_summary(payload, enabled=True, cache_dir=repo_summary_cache_dir)
            model_output = enrichment.pop("model_output", None)
            if model_output:
                repo.create_model_call(conn, run_id=run_id, agent_name="repo_summary", model_profile="configured_model", provider=str(model_output.get("provider") or "unknown"), status=str(model_output.get("status") or "success"), input_payload={"item_key": payload.get("item_key"), "title": payload.get("title"), "description_original": payload.get("description_original"), "security_summary": payload.get("security_summary")}, output_payload=model_output)
            payload = {**payload, **enrichment}
            enriched_summaries += 1
        payload = _finalize_summary(payload)
        payload = {**payload, "scoring": scoring.as_payload(), "vulnerability_signals": scoring.signals, "attack_surface": scoring.signals.get("attack_surface")}
        filtered = bool(scoring.signals.get("filtered"))
        domain_id = repo.create_domain_item(
            conn,
            domain="threats",
            item_type=item_type,
            title=payload.get("title") or "未命名威胁对象",
            summary=payload.get("summary") or "来自威胁 raw pipeline，待风险研判。",
            score=scoring.score,
            status="平台规则过滤" if filtered else "高风险待研判" if scoring.priority in {"critical", "high"} and item_type == "target" else "待研判" if item_type == "target" else "资产线索",
            source=payload.get("source") or "huawei_raw",
            source_url=payload.get("url") or "",
            primary_date=payload.get("primary_date") or "",
            tags=["connector_pipeline", payload.get("source_type") or "asset", scoring.grade, scoring.signals.get("attack_surface_grade"), payload.get("risk_grade") or ""],
            metrics={"pipeline_run": run_id, "risk_score": scoring.score, "score_breakdown": scoring.breakdown, "filtered": filtered, "filtered_reason": scoring.signals.get("filtered_reason")},
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
            payload={"run_id": run_id, "item_key": payload.get("item_key"), "scoring": scoring.as_payload()},
        )
        evidence += 1
        if scoring.score >= 80 and not filtered:
            repo.create_human_queue_item(
                conn,
                domain="threats",
                item_id=domain_id,
                queue_type="high_risk_target_review",
                priority=1,
                reason="Raw pipeline 识别到高风险目标，建议人工确认是否加入跟踪队列。",
                payload={"run_id": run_id, "item_key": payload.get("item_key")},
            )
    return {"items": targets, "evidence": evidence, "merged_inputs": len(items), "enriched_summaries": enriched_summaries}


def _merge_canonical_payloads(items: list[dict]) -> list[dict[str, Any]]:
    repo_payloads: dict[str, dict[str, Any]] = {}
    assets: list[dict[str, Any]] = []
    for item in items:
        payload = _normalized_payload(item)
        if not payload:
            continue
        if payload.get("source_type") in {"repo", "repo_cve"}:
            key = str(payload.get("item_key") or payload.get("title") or "").lower()
            if key:
                repo_payloads[key] = _merge_repo_payload(repo_payloads.get(key), payload)
            continue
        assets.append(payload)
    return [*repo_payloads.values(), *assets]


def _normalized_payload(item: dict[str, Any]) -> dict[str, Any]:
    if "normalized_json" in item:
        payload = repo.loads(item.get("normalized_json"), {})
    elif isinstance(item.get("normalized"), dict):
        payload = item["normalized"]
    else:
        payload = item
    return payload if isinstance(payload, dict) else {}


def _merge_repo_payload(existing: dict[str, Any] | None, incoming: dict[str, Any]) -> dict[str, Any]:
    if not existing:
        base = dict(incoming)
        if base.get("source_type") == "repo_cve":
            base["source_type"] = "repo"
        return base
    repo_payload, cve_payload = (incoming, existing) if incoming.get("source_type") == "repo" else (existing, incoming)
    merged = {**existing, **{key: value for key, value in incoming.items() if value not in (None, "", [])}}
    merged["source_type"] = "repo"
    merged["source"] = "+".join(sorted({str(existing.get("source") or ""), str(incoming.get("source") or "")} - {""})) or merged.get("source")
    merged["title"] = repo_payload.get("title") or existing.get("title") or incoming.get("title")
    merged["url"] = repo_payload.get("url") or existing.get("url") or incoming.get("url") or ""
    repo_summary = repo_payload.get("description_original") or repo_payload.get("summary_original") or (repo_payload.get("summary") if repo_payload.get("source_type") == "repo" else "")
    if repo_summary:
        merged["description_original"] = repo_summary
        merged["summary_original"] = repo_summary
        merged["summary"] = repo_summary
        merged["summary_source"] = "repo_description"
    if cve_payload.get("security_summary"):
        merged["security_summary"] = cve_payload.get("security_summary")
    for key in ["cve_count", "sa_count", "broad_sec_count", "total_sec_items", "security_items"]:
        merged[key] = max(_safe_int(existing.get(key)), _safe_int(incoming.get(key)))
    for key in ["cves", "sa_items", "broad_sec_items"]:
        merged[key] = _dedupe_list([*(existing.get(key) or []), *(incoming.get(key) or [])])
    merged["risk_score"] = max(_safe_float(existing.get("risk_score")) or 0.0, _safe_float(incoming.get("risk_score")) or 0.0)
    if isinstance(repo_payload.get("raw"), dict):
        merged["raw"] = repo_payload.get("raw")
    if incoming.get("source_type") == "repo_cve":
        merged["security_raw"] = incoming.get("raw")
    elif existing.get("source_type") == "repo_cve":
        merged["security_raw"] = existing.get("raw")
    merged["merged_sources"] = sorted({*(existing.get("merged_sources") or [existing.get("source")]), *(incoming.get("merged_sources") or [incoming.get("source")])} - {None, ""})
    return merged


def _summary_enrichment_keys(scored_payloads: list[tuple[dict[str, Any], str, Any]], limit: int) -> set[str]:
    if limit <= 0:
        return set()
    candidates = [(payload, scoring) for payload, item_type, scoring in scored_payloads if item_type == "target" and payload.get("item_key")]
    candidates.sort(key=lambda row: (-float(row[1].score or 0), str(row[0].get("item_key") or "")))
    return {str(payload.get("item_key")) for payload, _ in candidates[:limit]}


def _finalize_summary(payload: dict[str, Any]) -> dict[str, Any]:
    description = payload.get("description_original") or payload.get("summary_original") or ""
    security_summary = payload.get("security_summary") or ""
    summary = payload.get("summary_zh") or description or payload.get("summary") or security_summary or "来自威胁 raw pipeline，待风险研判。"
    source = payload.get("summary_source") or ("repo_description" if description else "security_summary" if security_summary else "fallback")
    return {**payload, "summary": summary, "summary_source": source}


def _dedupe_list(values: list[Any]) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for value in values:
        key = repo.dumps(value) if isinstance(value, (dict, list)) else str(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
