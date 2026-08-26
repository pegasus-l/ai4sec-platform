from __future__ import annotations

import io
import re
import sqlite3
import zipfile
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from ai4sec_platform.app.dependencies import get_db
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.domains.vulnerabilities.keyword_profiles import list_keyword_profiles
from ai4sec_platform.domains.vulnerabilities.pattern_synthesizers import render_pattern_markdown
from ai4sec_platform.domains.vulnerabilities import service as vuln_service
from ai4sec_platform.services import domain_items
from ai4sec_platform.services import operations

router = APIRouter(prefix="/vulnerabilities", tags=["vulnerabilities"])
DOMAIN = "vulnerabilities"


def _compact_stage_list(conn: sqlite3.Connection, item_type: str, limit: int) -> dict:
    data = domain_items.list_items(conn, DOMAIN, item_type=item_type, limit=limit)
    data["items"] = [_compact_stage_item(item) for item in data["items"]]
    return data


def _compact_stage_item(item: dict) -> dict:
    payload = item.get("payload") or {}
    compact_payload = {
        key: payload.get(key)
        for key in ("failure_reason", "error", "attempt_count", "crawl_mode", "search_keyword", "decision", "confidence", "reason")
        if payload.get(key) is not None
    }
    return {
        key: value
        for key, value in {**item, "payload": compact_payload}.items()
        if key not in {"evidence"}
    }


class FieldReviewRequest(BaseModel):
    reviewer: str = "shadow_operator"
    value: object | None = None
    reason: str = ""
    evidence_ids: list[int] = []


class BulkDownloadRequest(BaseModel):
    item_ids: list[int] | None = None


def _str_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _material_markdown(item: dict) -> str:
    """把单条素材渲染成可下载的 markdown 文档：元信息 + 摘要 + 正文 + 关键发现 + 证据片段 + 审核结论。"""
    payload = item.get("payload") or {}
    source = item.get("source_url") or item.get("source") or payload.get("source_host") or ""
    cves = _str_list(payload.get("cve_ids"))
    cwes = _str_list(payload.get("cwe_ids"))
    products = _str_list(payload.get("affected_products"))
    findings = _str_list(payload.get("key_findings"))
    snippets = payload.get("evidence_snippets") or payload.get("extracted_evidence", {}).get("evidence_snippets") or []
    body = str(payload.get("cleaned_text") or payload.get("markdown") or "").strip()
    lines = [
        f"# {item.get('title') or '未命名漏洞素材'}",
        "",
        f"> 原文：{source or '未知'}",
        "",
        "## 素材元信息",
        "",
        f"- 素材 ID：{item.get('id')}",
        f"- 状态：{item.get('status') or ''}",
        f"- 评分：{item.get('score') or ''}",
        f"- 类型：{payload.get('material_type') or payload.get('classification', {}).get('category') or ''}",
        f"- CVE：{', '.join(cves) or '无'}",
        f"- CWE：{', '.join(cwes) or '无'}",
        f"- 影响产品：{', '.join(products) or '无'}",
        "",
        "## 摘要",
        "",
        str(item.get("summary") or payload.get("summary") or "暂无摘要"),
        "",
    ]
    if body:
        lines.extend(["## 正文", "", body, ""])
    lines.extend(["## 关键发现", ""])
    if findings:
        lines.extend(f"- {finding}" for finding in findings)
    else:
        lines.append("- 无")
    lines.extend(["", "## 证据片段", ""])
    for snippet in snippets:
        if isinstance(snippet, dict):
            lines.append(f"- [{snippet.get('snippet_type')}] {str(snippet.get('content') or '')[:2000]}")
    for evidence in item.get("evidence") or []:
        if isinstance(evidence, dict):
            lines.append(f"- {str(evidence.get('content') or '')[:2000]}")
    if not snippets and not item.get("evidence"):
        lines.append("- 无")
    lines.extend(["", "## 审核结论", "", str(payload.get("check_reason") or payload.get("reason") or "无")])
    return "\n".join(lines)


def _download_filename(item: dict, prefix: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", str(item.get("title") or ""))[:60].strip("_")
    return f"{prefix}_{item.get('id')}_{safe or 'material'}.md"


@router.get("/keyword-profiles")
def keyword_profiles() -> dict:
    settings = load_settings()
    return {"items": list_keyword_profiles(settings.project_root, settings.output_dir)}


@router.get("/runs/{run_id}/results")
def run_results(run_id: str, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    run = conn.execute("SELECT summary_json FROM pipeline_runs WHERE run_id = ?", (run_id,)).fetchone()
    summary = repo.loads(run["summary_json"], {}) if run else {}
    child_run_ids = [str(value) for value in summary.get("child_run_ids") or []]
    for step in summary.get("steps") or []:
        for child_run_id in (step.get("metrics") or {}).get("child_run_ids") or []:
            if str(child_run_id) not in child_run_ids:
                child_run_ids.append(str(child_run_id))
    included_run_ids = [run_id, *child_run_ids]
    placeholders = ",".join("?" for _ in included_run_ids)
    rows = conn.execute(
        f"""
        SELECT * FROM domain_items
        WHERE domain = ? AND (
            json_extract(metrics_json, '$.pipeline_run') IN ({placeholders})
            OR EXISTS (
                SELECT 1 FROM json_each(domain_items.metrics_json, '$.pipeline_runs')
                WHERE json_each.value IN ({placeholders})
            )
        )
        ORDER BY id ASC
        """,
        (DOMAIN, *included_run_ids, *included_run_ids),
    ).fetchall()
    stages: dict[str, list[dict]] = {}
    for row in rows:
        item = _compact_stage_item(repo.row_to_dict(row))
        stages.setdefault(str(item["item_type"]), []).append(item)
    return {
        "run_id": run_id,
        "child_run_ids": child_run_ids,
        "count": len(rows),
        "stages": stages,
    }


@router.get("/runs")
def runs(limit: int = Query(20, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    rows = conn.execute(
        """
        SELECT * FROM pipeline_runs
        WHERE domain = ?
          AND COALESCE(json_extract(summary_json, '$.params.batch_parent_run_id'), '') = ''
        ORDER BY id DESC LIMIT ?
        """,
        (DOMAIN, limit),
    ).fetchall()
    items = []
    for row in rows:
        item = repo.row_to_dict(row)
        summary = item.get("summary") or {}
        item["summary"] = {
            "status": summary.get("status"),
            "error_message": summary.get("error_message"),
            "current_step": summary.get("current_step"),
            "completed_steps": summary.get("completed_steps"),
            "total_steps": summary.get("total_steps"),
            "batch_progress": summary.get("batch_progress"),
        }
        items.append(item)
    return {"items": items}


@router.get("/today")
def today(limit: int = Query(200, ge=1, le=500), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return vuln_service.today(conn, limit=limit)


@router.get("/materials")
def materials(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return domain_items.list_items(conn, DOMAIN, item_type="material", limit=limit)


@router.get("/candidates")
def candidates(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _compact_stage_list(conn, "search_candidate", limit)


@router.get("/crawled-pages")
def crawled_pages(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _compact_stage_list(conn, "crawled_page", limit)


@router.get("/extracted-content")
def extracted_content(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _compact_stage_list(conn, "extracted_content", limit)


@router.get("/material-reviews")
def material_reviews(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _compact_stage_list(conn, "material_review", limit)


@router.get("/evaluations")
def evaluations(limit: int = Query(20, ge=1, le=100), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    rows = conn.execute(
        "SELECT * FROM domain_items WHERE domain = ? AND item_type = ? ORDER BY id DESC LIMIT ?",
        (DOMAIN, "shadow_evaluation", limit),
    ).fetchall()
    items = [repo.row_to_dict(row) for row in rows]
    return {"domain": DOMAIN, "count": len(items), "items": items}


@router.get("/materials/{item_id}")
def material_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="material not found")
    return item


@router.get("/materials/{item_id}/download")
def material_download(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> Response:
    """漏洞素材一键下载：把单条素材渲染为 markdown 附件返回。"""
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="material not found")
    return Response(
        _material_markdown(item),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_download_filename(item, "vuln_material")}"'},
    )


@router.post("/materials/bulk-download")
def materials_bulk_download(request: BulkDownloadRequest, conn: sqlite3.Connection = Depends(get_db)) -> Response:
    """漏洞素材批量下载：按 item_ids 打包 zip；不传 ids 时下载全部素材。"""
    if request.item_ids:
        placeholders = ",".join("?" for _ in request.item_ids)
        rows = conn.execute(
            f"SELECT * FROM domain_items WHERE domain = ? AND item_type = ? AND id IN ({placeholders}) ORDER BY id",
            (DOMAIN, "material", *request.item_ids),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM domain_items WHERE domain = ? AND item_type = ? ORDER BY id",
            (DOMAIN, "material"),
        ).fetchall()
    if not rows:
        raise HTTPException(status_code=404, detail="no materials found")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for row in rows:
            item = repo.row_to_dict(row)
            archive.writestr(_download_filename(item, "vuln_material"), _material_markdown(item))
    buffer.seek(0)
    return Response(
        buffer.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="vuln_materials_bulk.zip"'},
    )


@router.get("/events")
def events(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return vuln_service.events(conn, limit=limit)


@router.get("/patterns")
def patterns(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    data = domain_items.list_items(conn, DOMAIN, item_type="vulnerability_pattern", limit=limit)
    for item in data["items"]:
        payload = item.get("payload")
        if isinstance(payload, dict):
            payload.pop("model_output", None)  # 列表接口不返回完整模型输出, 保持轻量
    return data


@router.get("/patterns/{item_id}")
def pattern_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "vulnerability_pattern":
        raise HTTPException(status_code=404, detail="pattern not found")
    return item


@router.get("/patterns/{item_id}/download")
def pattern_download(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> Response:
    """漏洞模式 markdown 一键下载。"""
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "vulnerability_pattern":
        raise HTTPException(status_code=404, detail="pattern not found")
    return Response(
        render_pattern_markdown(item),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_download_filename(item, "vuln_pattern")}"'},
    )


@router.get("/events/{item_id}")
def event_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = vuln_service.event_detail(conn, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="event not found")
    return item


@router.get("/extractions")
def extractions(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return vuln_service.extractions(conn, limit=limit)


@router.get("/knowledge")
def knowledge(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    data = domain_items.list_items(conn, DOMAIN, item_type="knowledge", limit=50)
    return {
        "domain": DOMAIN,
        "items": [
            {
                "item_id": item["id"],
                "title": item["title"],
                "status": item["status"],
                "summary": item.get("summary", ""),
                "source_material_id": item.get("payload", {}).get("source_material_id"),
                "key_findings": item.get("payload", {}).get("key_findings", []),
                "verification_clues": item.get("payload", {}).get("verification_clues", []),
            }
            for item in data["items"]
        ],
    }


@router.get("/knowledge/{item_id}")
def knowledge_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "knowledge":
        raise HTTPException(status_code=404, detail="knowledge not found")
    return item


@router.get("/knowledge/{item_id}/model-snippet")
def knowledge_model_snippet(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "knowledge":
        raise HTTPException(status_code=404, detail="knowledge not found")
    payload = item.get("payload") or {}
    snippet = "\n".join(
        [
            f"【漏洞类型】{payload.get('vulnerability_type', '')}",
            f"【CVE】{', '.join(payload.get('cve_ids') or [])}",
            f"【CWE】{', '.join(payload.get('cwe_ids') or [])}",
            f"【根因】{payload.get('root_cause_pattern', '')}",
            f"【触发条件】{payload.get('trigger_condition', '')}",
            f"【攻击入口】{payload.get('attack_entry', '')}",
            f"【关键函数/API】{', '.join(payload.get('key_functions_or_apis') or [])}",
            f"【修复策略】{payload.get('mitigation_or_fix', '')}",
        ]
    )
    return {"knowledge_id": item_id, "title": item.get("title"), "snippet": snippet}


@router.post("/knowledge/{item_id}/fields/{field_name}/accept")
def accept_field(item_id: int, field_name: str, request: FieldReviewRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return vuln_service.accept_field(conn, item_id, field_name, reviewer=request.reviewer, reason=request.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/knowledge/{item_id}/fields/{field_name}/modify")
def modify_field(item_id: int, field_name: str, request: FieldReviewRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return vuln_service.modify_field(conn, item_id, field_name, request.value, reviewer=request.reviewer, reason=request.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/knowledge/{item_id}/fields/{field_name}/reject")
def reject_field(item_id: int, field_name: str, request: FieldReviewRequest, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return vuln_service.reject_field(conn, item_id, field_name, reviewer=request.reviewer, reason=request.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/migration-queue")
def migration_queue(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return operations.human_queue(conn, DOMAIN)
