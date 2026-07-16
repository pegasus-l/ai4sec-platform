from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from ai4sec_platform.core.config import Settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.importers.ai_for_sec import import_ai_for_sec
from ai4sec_platform.importers.huawei import import_huawei
from ai4sec_platform.importers.vulnerability_materials import import_vulnerability_materials


def import_all_legacy_samples(conn: sqlite3.Connection, settings: Settings) -> dict[str, Any]:
    sources = settings.legacy_sources
    limits = settings.import_limits
    results: dict[str, Any] = {}
    ai_raw_dir = Path(sources.get("ai_for_sec_raw_dir", ""))
    if ai_raw_dir.exists():
        results["ai_for_sec"] = import_ai_for_sec(conn, ai_raw_dir, limit_news=int(limits.get("news", 20)), limit_capabilities=int(limits.get("capabilities", 12)))
    else:
        results["ai_for_sec"] = {"error": f"missing {ai_raw_dir}"}
        repo.create_quality_audit(conn, domain="news", audit_type="legacy_import", status="fail", score=0.0, summary="AI-for-Sec raw 目录不存在。", details={"path": str(ai_raw_dir)})

    huawei_dir = Path(sources.get("huawei_dir", ""))
    if huawei_dir.exists():
        results["huawei"] = import_huawei(conn, huawei_dir, limit=int(limits.get("threats", 20)))
    else:
        results["huawei"] = {"error": f"missing {huawei_dir}"}
        repo.create_quality_audit(conn, domain="threats", audit_type="legacy_import", status="fail", score=0.0, summary="华为情报目录不存在。", details={"path": str(huawei_dir)})

    vulnerability_dir = Path(sources.get("vulnerability_dir", ""))
    if vulnerability_dir.exists():
        results["vulnerabilities"] = import_vulnerability_materials(conn, vulnerability_dir, limit=int(limits.get("vulnerabilities", 20)))
    else:
        results["vulnerabilities"] = {"error": f"missing {vulnerability_dir}"}
        repo.create_quality_audit(conn, domain="vulnerabilities", audit_type="legacy_import", status="fail", score=0.0, summary="漏洞素材目录不存在。", details={"path": str(vulnerability_dir)})

    _seed_operations_placeholders(conn)
    conn.commit()
    return results


def _seed_operations_placeholders(conn: sqlite3.Connection) -> None:
    repo.create_data_source(conn, domain="operations", name="Front-end demo v3", source_type="product_reference", status="ok", health="ok", summary={"path": "/mnt/d/漏洞挖掘/洞察工具/dashboard/demo/index-v3.html"})
    repo.create_quality_audit(conn, domain="operations", audit_type="first_stage_scope", status="pass", score=1.0, summary="第一阶段仅导入旧数据并提供页面展示 API，不做采集、模型重跑或复现执行。", details={"production_writes": False})
    repo.create_human_queue_item(conn, domain="operations", item_id=None, queue_type="architecture_review", priority=2, reason="确认第一阶段 API 返回结构是否满足 demo 页面展示。", payload={"document": "docs/平台总体架构设计.md"})
