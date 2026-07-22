from __future__ import annotations

import sqlite3
from typing import Any

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.threats.service import latest_artifact_preview
from ai4sec_platform.services import domain_items, operations


def page_contract(conn: sqlite3.Connection) -> dict[str, Any]:
    news_items = _items(domain_items.list_items(conn, "news", limit=100))
    capability_items = _items(domain_items.list_items(conn, "capabilities", limit=100))
    threat_targets = _items(domain_items.list_items(conn, "threats", item_type="target", limit=100))
    vuln_materials = _items(domain_items.list_items(conn, "vulnerabilities", item_type="material", limit=100))
    vuln_knowledge = _items(domain_items.list_items(conn, "vulnerabilities", item_type="knowledge", limit=100))
    return {
        "manifest": _manifest(conn),
        "news": {
            "asisPage": _asis_page(news_items),
            "sources": _news_sources(conn, news_items),
            "items": [_news_item(item) for item in news_items],
        },
        "capability": {
            "today": [_capability_item(item) for item in capability_items[:30]],
            "library": [_capability_item(item) for item in capability_items],
            "reproRuns": _capability_repro_runs(capability_items),
            "conversions": _capability_conversions(capability_items),
        },
        "threat": {
            "today": [_threat_item(item) for item in threat_targets[:30]],
            "targets": [_threat_item(item) for item in threat_targets],
            "assets": [_threat_item(item) for item in _items(domain_items.list_items(conn, "threats", item_type="asset", limit=300))],
            "tracking": operations.human_queue(conn, "threats")["items"],
            "graph": _threat_graph(threat_targets),
            "riskAssessments": [_risk_assessment(item) for item in threat_targets if (item.get("payload") or {}).get("risk_assessment")],
            "cveScout": latest_artifact_preview(conn, "huawei_cve_scout"),
            "attackSurface": latest_artifact_preview(conn, "huawei_attack_surface"),
            "reports": latest_artifact_preview(conn, "huawei_threat_report"),
        },
        "vuln": {
            "today": [_vuln_material(item) for item in vuln_materials[:30]],
            "materials": [_vuln_material(item) for item in vuln_materials],
            "knowledge": [_vuln_knowledge(item) for item in vuln_knowledge],
            "migration": operations.human_queue(conn, "vulnerabilities")["items"],
        },
        "ops": {
            "tasks": operations.tasks(conn)["items"],
            "sources": operations.sources(conn)["items"],
            "rules": operations.rules()["items"],
            "quality": operations.audits(conn)["items"],
            "queue": operations.human_queue(conn)["items"],
            "modelCalls": operations.model_calls(conn),
        },
    }


def static_file_contract(conn: sqlite3.Connection, path: str) -> Any:
    data = page_contract(conn)
    mapping = {
        "manifest.json": data["manifest"],
        "news/asis_page.json": data["news"]["asisPage"],
        "news/sources.json": data["news"]["sources"],
        "news/items.json": data["news"]["items"],
        "capability/today.json": data["capability"]["today"],
        "capability/library.json": data["capability"]["library"],
        "capability/repro_runs.json": data["capability"]["reproRuns"],
        "capability/conversions.json": data["capability"]["conversions"],
        "threat/today.json": data["threat"]["today"],
        "threat/targets.json": data["threat"]["targets"],
        "threat/assets.json": data["threat"]["assets"],
        "threat/tracking.json": data["threat"]["tracking"],
        "threat/graph.json": data["threat"]["graph"],
        "threat/cve_scout.json": data["threat"]["cveScout"],
        "threat/attack_surface.json": data["threat"]["attackSurface"],
        "threat/reports.json": data["threat"]["reports"],
        "vuln/today_materials.json": data["vuln"]["today"],
        "vuln/materials.json": data["vuln"]["materials"],
        "vuln/knowledge_items.json": data["vuln"]["knowledge"],
        "vuln/migration_queue.json": data["vuln"]["migration"],
        "ops/tasks.json": data["ops"]["tasks"],
        "ops/sources.json": data["ops"]["sources"],
        "ops/rules.json": data["ops"]["rules"],
        "ops/quality_findings.json": data["ops"]["quality"],
        "ops/queue_items.json": data["ops"]["queue"],
    }
    return mapping.get(path)


def _items(result: dict[str, Any]) -> list[dict[str, Any]]:
    return list(result.get("items") or [])


def _manifest(conn: sqlite3.Connection) -> dict[str, Any]:
    settings = load_settings()
    return {
        "name": "AI4SEC TMG",
        "version": "v9-backend-contract",
        "generated_at": utc_now(),
        "data_mode": "connector_pipeline",
        "production_writes": settings.production_writes,
        "counts": {
            "news": repo.count_by_domain(conn, "news"),
            "capabilities": repo.count_by_domain(conn, "capabilities"),
            "threats": repo.count_by_domain(conn, "threats"),
            "vulnerabilities": repo.count_by_domain(conn, "vulnerabilities"),
        },
    }


def _asis_page(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "title": "资讯洞察",
        "subtitle": "复用 ASIS 阅读体验，数据来自本地 AI-for-Sec raw JSON 导入后的新处理链路。",
        "nav": ["精选", "全部动态", "日报", "论文", "阅读清单", "专题时间线"],
        "total": len(items),
    }


def _news_sources(conn: sqlite3.Connection, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for item in items:
        source = item.get("source") or "unknown"
        counts[source] = counts.get(source, 0) + 1
    if not counts:
        for source in operations.sources(conn, "news")["items"]:
            counts[source.get("name") or source.get("source_type") or "unknown"] = 0
    return [{"id": key, "name": key, "count": value, "status": "connector_pipeline"} for key, value in sorted(counts.items())]


def _news_item(item: dict[str, Any]) -> dict[str, Any]:
    payload = item.get("payload") or {}
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "subtitle": payload.get("title") or item.get("title"),
        "summary": item.get("summary"),
        "highlight": item.get("summary"),
        "source": item.get("source"),
        "source_url": item.get("source_url"),
        "category": payload.get("source_type") or item.get("item_type"),
        "score": item.get("score"),
        "tags": item.get("tags") or [],
        "tech_points": payload.get("tech_points") or payload.get("topics") or [],
        "published_at": item.get("primary_date"),
    }


def _capability_item(item: dict[str, Any]) -> dict[str, Any]:
    payload = item.get("payload") or {}
    assessment = payload.get("assessment") or {}
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "summary": item.get("summary"),
        "source_url": item.get("source_url"),
        "score": item.get("score"),
        "status": item.get("status"),
        "repro_status": "待复现验证" if item.get("status") == "待复现验证" else "待评估",
        "conversion_status": "待转化评估",
        "application_scenarios": payload.get("application_scenarios") or [],
        "assessment": assessment,
    }


def _capability_repro_runs(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"id": f"repro-{item['id']}", "capability_id": item["id"], "title": item["title"], "status": item.get("status"), "runner": "local-rule-queue", "next_action": "确认依赖、数据集和最小复现命令"} for item in items[:30]]


def _capability_conversions(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"id": f"conversion-{item['id']}", "capability_id": item["id"], "title": item["title"], "status": "待转化评估", "target": "检测/分析/自动化能力"} for item in items[:30]]


def _threat_item(item: dict[str, Any]) -> dict[str, Any]:
    payload = item.get("payload") or {}
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "summary": payload.get("summary_zh") or item.get("summary"),
        "security_summary": payload.get("security_summary"),
        "summary_source": payload.get("summary_source"),
        "score": item.get("score"),
        "status": item.get("status"),
        "source_url": item.get("source_url"),
        "risk_grade": payload.get("risk_grade"),
        "risk_assessment": payload.get("risk_assessment"),
        "tags": item.get("tags") or [],
        "signals": payload,
    }


def _risk_assessment(item: dict[str, Any]) -> dict[str, Any]:
    return {"target_id": item.get("id"), "title": item.get("title"), **((item.get("payload") or {}).get("risk_assessment") or {})}


def _threat_graph(items: list[dict[str, Any]]) -> dict[str, Any]:
    nodes = [{"id": f"target:{item['id']}", "label": item.get("title"), "type": "target", "score": item.get("score")} for item in items[:100]]
    return {"nodes": nodes, "edges": [], "status": "partial"}


def _vuln_material(item: dict[str, Any]) -> dict[str, Any]:
    payload = item.get("payload") or {}
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "summary": item.get("summary"),
        "url": item.get("source_url"),
        "score": item.get("score"),
        "status": item.get("status"),
        "category": payload.get("category"),
        "confidence": payload.get("confidence"),
        "key_findings": payload.get("key_findings") or [],
    }


def _vuln_knowledge(item: dict[str, Any]) -> dict[str, Any]:
    payload = item.get("payload") or {}
    return {
        "id": item.get("id"),
        "title": item.get("title"),
        "summary": item.get("summary"),
        "status": item.get("status"),
        "source_material_id": payload.get("source_material_id"),
        "key_findings": payload.get("key_findings") or [],
        "verification_clues": payload.get("verification_clues") or [],
    }
