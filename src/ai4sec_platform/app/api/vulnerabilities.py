from __future__ import annotations

import io
import json
import re
import sqlite3
import zipfile
from typing import Any
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from ai4sec_platform.app.dependencies import current_user, get_db
from ai4sec_platform.app.api.runs import start_pipeline_run
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.core.config import load_settings
from ai4sec_platform.domains.vulnerabilities import cases as case_service
from ai4sec_platform.domains.vulnerabilities import links as case_links
from ai4sec_platform.domains.vulnerabilities import projects as project_service
from ai4sec_platform.domains.vulnerabilities import manual_ingest, manual_keywords
from ai4sec_platform.domains.vulnerabilities.keyword_profiles import (
    list_keyword_categories,
    list_keyword_profiles,
    load_keyword_rotation_state,
    resolve_keyword_profile,
)
from ai4sec_platform.domains.vulnerabilities.comprehension_probers import aggregate_feedback, render_probe_markdown
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
    # 服务端分页后前端不再持有"全部命中的 id", 改成把筛选条件发过来(见 materials_bulk_download)
    q: str | None = None
    chip: str | None = None


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
def keyword_profiles(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    settings = load_settings()
    items = list_keyword_profiles(settings.project_root, settings.output_dir)
    # 顺带回带"每个 profile 已存几条人工关键词"(2026-10-10),省前端一次请求 ——
    # 页面上"这个 profile 配了 60 个词"和"其中 3 个是人工加的"要一起看到。
    # `*`(所有 profile 通用)的词对每个 profile 都算数。
    counts = manual_keywords.count_by_profile(conn)
    wildcard = counts.get(manual_keywords.WILDCARD_PROFILE, 0)
    for item in items:
        item["manual_queries"] = counts.get(str(item.get("name") or ""), 0) + wildcard
    return {
        "items": items,
        "wildcard_manual_queries": wildcard,
        "max_manual_queries": manual_keywords.MAX_PER_PROFILE,
    }


@router.get("/keyword-categories")
def keyword_categories() -> dict:
    """词表里 18 个漏洞大类各自的全部关键词(2026-10-15)。

    页面问"每个类别的关键词都是啥"就走这条;`/keyword-profiles` 只回计数。
    与 profile 一样,不在这里过滤 `hidden` —— 收起与否是页面的决定。
    """
    settings = load_settings()
    return {"items": list_keyword_categories(settings.project_root)}


class AddManualKeywordRequest(BaseModel):
    profile_name: str = ""
    keyword: str = ""
    label: str = ""
    note: str = ""


def _nightly_dispatch_preview(conn: sqlite3.Connection) -> dict:
    """今晚那条定时跑批**实际会下发多少条查询**(2026-10-16)。

    口径必须和今晚真正下发的一致,否则页面上那个数字就是骗人的:用**与采集路径相同**的
    params 解析 profile(见 pipelines/steps/vulnerability_discovery.py 里 keyword_profile
    + 轮换游标那两行),再走**纯函数**合并人工词,得出去重后的真实条数。

    这是**只读**预览 —— 绝不能调 mark_manual_queries_used:那样页面一打开就把所有词标成
    "已下发",生效证据立刻变假。合并函数保持纯函数正是为了这里能安全地预览。
    """
    settings = load_settings()
    name = manual_keywords.NIGHTLY_PROFILE
    preview = {"profile": name, "base": 0, "manual": 0, "total": 0, "dropped": 0, "error": ""}
    try:
        state = load_keyword_rotation_state(settings.output_dir, name)
        profile = resolve_keyword_profile(
            {"keyword_profile": name, "_rotation_offset": state.get("cursor", 0)},
            settings.project_root,
        )
        if profile is None:
            return preview
        base = list(profile.queries)
        merged, metrics = manual_keywords.merge_manual_queries(conn, name, base)
    except Exception as exc:  # noqa: BLE001 - 预览算不出来不该让整个页面 500
        preview["error"] = str(exc)
        return preview
    preview["base"] = len(base)
    # manual 报的是**去重前**的启用条数,便于和列表里的条数对照
    preview["manual"] = int(metrics.get("manual_queries") or 0)
    preview["total"] = len(merged)
    # 没进下发的人工词条数(与 profile 自带词重名、或人工词之间重名)
    preview["dropped"] = preview["base"] + preview["manual"] - preview["total"]
    return preview


@router.get("/manual-keywords")
def list_manual_keywords(profile: str = Query(default=""), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """人工添加的漏洞检索关键词(停用的也返回,页面显示为删除线)。"""
    return {
        "items": manual_keywords.list_keywords(conn, profile_name=profile or None),
        "max_per_profile": manual_keywords.MAX_PER_PROFILE,
        "wildcard_profile": manual_keywords.WILDCARD_PROFILE,
        # 生效范围收敛成一档(2026-10-16):原先给的是"所有漏洞检索 / 仅每晚跑批"两档,但这两者
        # 在当前系统里**没有任何区别** —— 唯一的定时跑批写死 daily_watch,而取数 SQL 是
        # `profile_name=? OR profile_name='*'`。没有后果的选择不该让人做,所以只留 `*`(它是唯一
        # 不会因为某个调度档上线/下线而悄悄失效的范围)。字段仍是数组:页面照旧读 [0] 的标签与说明,
        # 将来真出现第二个有意义的范围时不必改页面结构。
        "scope_options": [
            {
                "value": manual_keywords.WILDCARD_PROFILE,
                "label": "所有漏洞检索",
                "hint": "任何漏洞检索跑批都会带上它,换了 profile 也不会悄悄失效。",
            },
        ],
        "nightly_profile": manual_keywords.NIGHTLY_PROFILE,
        "nightly_preview": _nightly_dispatch_preview(conn),
    }


@router.post("/manual-keywords")
def add_manual_keyword(
    request: AddManualKeywordRequest,
    conn: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(current_user),
) -> dict:
    """人工添加检索关键词。**下一轮采集立即生效**,常驻(直到在本页停用)。"""
    try:
        return manual_keywords.add_keyword(
            conn,
            profile_name=request.profile_name,
            keyword=request.keyword,
            label=request.label,
            note=request.note,
            created_by=str(user.get("username") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/manual-keywords/{keyword_id}/enable")
def enable_manual_keyword(keyword_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    # 不带请求体:前端按 enabled 选 /enable 或 /disable 两个路径(与 ops.py 的
    # /sources/targets/{id}/enable 同一约定,避免少一个 JSON body 就 422)。
    return _toggle_manual_keyword(conn, keyword_id, True)


@router.post("/manual-keywords/{keyword_id}/disable")
def disable_manual_keyword(keyword_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return _toggle_manual_keyword(conn, keyword_id, False)


def _toggle_manual_keyword(conn: sqlite3.Connection, keyword_id: int, enabled: bool) -> dict:
    try:
        return manual_keywords.set_keyword_enabled(conn, keyword_id, enabled)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.delete("/manual-keywords/{keyword_id}")
def remove_manual_keyword(keyword_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    if not manual_keywords.delete_keyword(conn, keyword_id):
        raise HTTPException(status_code=404, detail="记录不存在")
    return {"status": "deleted", "id": keyword_id}


class ManualMaterialRequest(BaseModel):
    url: str = ""
    title: str = ""
    body: str = ""
    note: str = ""


@router.post("/materials/manual")
def ingest_manual_material(
    request: ManualMaterialRequest,
    user: dict = Depends(current_user),
) -> dict:
    """人工投喂一篇漏洞文章(URL 必填,正文可选;正文给了就不去抓页面)。

    **异步**:抓取 + 正文抽取 + 模型评审实测 30s 起,同步跑会撞上网关对非流式请求的 120s
    总时长上限 —— 同步就是大概率 502,而且活干了一半、连个 run 行都没有。这里立刻返回
    `{run_id, status, poll_url}`,前端拿 run_id 去轮询现成的进度组件。

    走的流水线是 `vulnerabilities.manual_material_ingest_pipeline`(入库 → 选知识候选 →
    抽知识),所以投喂完**当场**就能在知识库里看到候选,不用等当晚 22:00 的跑批。
    """
    try:
        url = manual_ingest.validate_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    body = str(request.body or "").strip()
    if body and len(body) < manual_ingest.MIN_PROVIDED_BODY_CHARS:
        raise HTTPException(
            status_code=400,
            detail=f"正文过短(至少 {manual_ingest.MIN_PROVIDED_BODY_CHARS} 字);只想让平台自己抓的话请把正文留空",
        )
    return start_pipeline_run(
        "vulnerabilities.manual_material_ingest_pipeline",
        {
            "manual_items": [{
                "url": url,
                "title": request.title,
                "body": body,
                "note": request.note,
                "created_by": str(user.get("username") or ""),
            }],
            # 兜底排空是给定时跑批用的:喂一条 URL 却连带抽 20 条无关积压,既费模型又费解。
            "pending_drain_limit": 0,
        },
    )


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
def materials(
    q: str | None = Query(None, max_length=200,
                          description="搜索关键词(标题/摘要/来源/根因/一句话/CVE/CWE)"),
    chip: str | None = Query(None,
                             description="芯片筛选: all/poc_exploit/tech_analysis/needs/confirmed(不传或 all = 全部)"),
    sort: str = Query("score", description="排序: score(分数优先, 默认) / recent(最新优先)"),
    page: int = Query(1, ge=1, description="页码(1-based)"),
    page_size: int = Query(20, ge=1, le=500, description="每页条数"),
    limit: int | None = Query(None, ge=1, le=500, deprecated=True,
                              description="已废弃: 请用 page_size。保留仅为兼容旧调用方, 给出时覆盖 page_size"),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    # 2026-09-17: 去掉 200 上限, 改服务端分页。库里有 313 条非「已淘汰」素材, 原先前端写死
    # limit=200 且排序是分数优先 —— 被砍掉的 113 条是**分数最低**的(横跨 08-20~09-15, 含昨晚新
    # 产出但分低的), 不是"旧素材", 页面上永远不可达。
    # 筛选/排序/分页都下推到 SQL, 谓词与 chip_counts 共用 db.repositories.MATERIAL_CHIP_PREDICATES,
    # 所以「芯片上的数字」「列表里的条数」「批量下载的条数」三者结构性同源。
    # 列表剥掉整页原文(单条可达 1.7MB), 详见 slim_material —— 分页后只需处理当页, 反而更省。
    if chip and chip not in repo.MATERIAL_CHIP_PREDICATES:
        # 静默忽略未知取值会表现为"筛选没生效", 比一个明确的 400 难查得多
        raise HTTPException(status_code=400,
                            detail=f"未知的 chip 取值: {chip!r}; 可选: {list(repo.MATERIAL_CHIP_PREDICATES)}")
    if sort not in repo.SORT_PREDICATES:
        raise HTTPException(status_code=400,
                            detail=f"未知的 sort 取值: {sort!r}; 可选: {list(repo.SORT_PREDICATES)}")
    return vuln_service.materials(conn, q=q, chip=chip, sort=sort, page=page,
                                  page_size=limit or page_size)


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
    """漏洞素材批量下载：按 item_ids 打包 zip；不传 ids 时按筛选条件打包命中的全部素材。

    2026-09-17: 素材列表改服务端分页后, 前端手里只剩"当前页 20 条"。若不动这里, 那个「批量下载
    (N)」按钮会**静默地**从"下载全部命中"退化成"只下载当前页" —— 改了哪些文件进 zip 是看不出来的。
    所以把筛选条件(q/chip)也收进来, 谓词与列表**共用同一套**
    (repo.MATERIAL_CHIP_PREDICATES + material haystack), 按钮上写的条数与打包出的条数同源。
    无筛选时 = 全部非「已淘汰」素材(与改前"不传 ids 下载全部素材"同义, 只是上限从 200 放开到 313)。
    """
    if request.item_ids:
        placeholders = ",".join("?" for _ in request.item_ids)
        rows = [repo.row_to_dict(row) for row in conn.execute(
            f"SELECT * FROM domain_items WHERE domain = ? AND item_type = ? AND id IN ({placeholders}) ORDER BY id",
            (DOMAIN, "material", *request.item_ids),
        ).fetchall()]
    else:
        chip = request.chip if request.chip != "all" else None
        if chip and chip not in repo.MATERIAL_CHIP_PREDICATES:
            raise HTTPException(status_code=400,
                                detail=f"未知的 chip 取值: {chip!r}; 可选: {list(repo.MATERIAL_CHIP_PREDICATES)}")
        # limit=-1: SQLite 语义里负 LIMIT 就是不限(与改前那条无 LIMIT 的裸 SQL 等价),
        # 走 repo 而不是裸 SQL 是为了拿到与列表逐字相同的 WHERE。
        rows = repo.list_domain_items(conn, DOMAIN, item_type="material", limit=-1,
                                      exclude_status="已淘汰",
                                      material_chips=[chip] if chip else None,
                                      haystack="material", q=request.q)
    if not rows:
        raise HTTPException(status_code=404, detail="no materials found")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for item in rows:
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


@router.get("/patterns/{item_id}/cases")
def pattern_cases(item_id: int, limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """模式 → 实例案例(P6a)。

    口径:模式来源文章的 CVE,或挂在同一批文章上的案例。它回答的是「这类洞在库里有哪些
    真实实例」,不是「模型判定这些案例属于该模式」—— 后者要等 P6b 用代码证据去判。
    列表为空时带 `note` 说明原因(没有来源素材 / 文章还没点名库里的洞),不返回一个空列表了事。
    """
    data = case_links.cases_for_pattern(conn, item_id, limit=limit)
    if data is None:
        raise HTTPException(status_code=404, detail="pattern not found")
    return data


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


@router.get("/comprehension")
def comprehension(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    data = domain_items.list_items(conn, DOMAIN, item_type="comprehension_probe", limit=limit)
    for item in data["items"]:
        payload = item.get("payload")
        if isinstance(payload, dict):
            payload.pop("model_output", None)  # 列表接口剥离完整模型输出, 保持轻量
    return data


@router.get("/comprehension/summary")
def comprehension_summary(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """通过率 + 各维度均分 + 回灌建议聚合。"""
    rows = conn.execute(
        "SELECT payload_json FROM domain_items WHERE domain = ? AND item_type = ?",
        (DOMAIN, "comprehension_probe"),
    ).fetchall()
    probes = []
    for row in rows:
        try:
            probes.append(json.loads(row["payload_json"]))
        except (ValueError, TypeError):
            continue
    if not probes:
        return {"tested": 0, "passed": 0, "failed": 0, "pass_rate": 0.0, "avg_score": 0.0, "dimension_averages": {}, "feedback": []}
    passed = sum(1 for p in probes if p.get("verdict") == "pass")
    scores = [p.get("overall_score") for p in probes if isinstance(p.get("overall_score"), (int, float))]
    avg = round(sum(scores) / len(scores), 2) if scores else 0.0
    dimension_averages: dict[str, float] = {}
    for dim in ("root_cause", "trigger_condition", "exploit_primitives", "mitigation"):
        vals = [p.get("per_field_scores", {}).get(dim) for p in probes if isinstance(p.get("per_field_scores"), dict)]
        numeric = [v for v in vals if isinstance(v, (int, float))]
        dimension_averages[dim] = round(sum(numeric) / len(numeric), 2) if numeric else 0.0
    return {
        "tested": len(probes),
        "passed": passed,
        "failed": len(probes) - passed,
        "pass_rate": round(passed / len(probes), 2),
        "avg_score": avg,
        "dimension_averages": dimension_averages,
        "feedback": aggregate_feedback(probes),
    }


@router.get("/comprehension/{item_id}")
def comprehension_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "comprehension_probe":
        raise HTTPException(status_code=404, detail="comprehension probe not found")
    return item


@router.get("/comprehension/{item_id}/download")
def comprehension_download(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> Response:
    """可理解性验证 markdown 一键下载。"""
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "comprehension_probe":
        raise HTTPException(status_code=404, detail="comprehension probe not found")
    return Response(
        render_probe_markdown(item),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_download_filename(item, "comprehension_probe")}"'},
    )


@router.get("/events/{item_id}")
def event_detail(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = vuln_service.event_detail(conn, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="event not found")
    return item


# ── 漏洞案例库(2026-10-16)────────────────────────────────────────────────────
# 一个洞一行(canonical_id 唯一),上下文在子表里。**列表不带 content** —— 代码片段只在详情里出现。

class CaseCreateRequest(BaseModel):
    # auto = 人贴一个 id,元数据等采集步去抓;manual = 完全手填(没有外部 id 的项目内部 bug)
    mode: str = "auto"
    canonical_id: str = ""
    title: str = ""
    summary: str = ""
    severity: str = ""
    cvss_score: float | None = None
    source_url: str = ""
    cwe_ids: list[str] = []
    affected_products: list[str] = []
    references: list[str] = []
    code: str = ""
    note: str = ""


class CaseUpdateRequest(BaseModel):
    title: str | None = None
    summary: str | None = None
    severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    status: str | None = None
    cwe_ids: list[str] | None = None
    affected_products: list[str] | None = None
    fixed_versions: list[str] | None = None
    references: list[str] | None = None


class CaseContextRequest(BaseModel):
    context_type: str = "manual_note"
    content: str = ""
    confidence: float | None = None
    repo: str = ""
    commit_sha: str = ""
    file_path: str = ""
    function_name: str = ""
    start_line: int = 0
    end_line: int = 0
    source_url: str = ""
    label: str = ""


class CaseSourceRequest(BaseModel):
    kind: str = "manual_id"
    identifier: str = ""
    source_key: str = ""
    label: str = ""
    note: str = ""


class ProjectRequest(BaseModel):
    # 仓地址(github:org/repo / https://github.com/org/repo / org/repo)
    url: str = ""
    display_name: str = ""
    # 字符串("pkg:pypi/django" / "Maven:group:artifact")或 {ecosystem,name}
    packages: list[Any] = []
    tier: str = "benchmark"
    # P5b:项目自有公告源。**不传 = 默认开 releases + changelog**;
    # 传空数组 = 用户明确不要任何自有源(页面上会显示"未配置")。
    native_sources: list[str] | None = None


class ProjectUpdateRequest(BaseModel):
    display_name: str | None = None
    packages: list[Any] | None = None
    tier: str | None = None
    native_sources: list[str] | None = None


class ProjectDetectRequest(BaseModel):
    url: str = ""


@router.get("/cases")
def list_cases(
    q: str = "",
    severity: str = "",
    id_kind: str = "",
    source: str = "",
    status: str = "",
    completeness: str = "",
    project_id: int = 0,
    curated: bool = False,
    published_from: str = "",
    published_to: str = "",
    created_since: str = "",
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    """案例列表。关键词/筛选**全部下推 SQL 分页**(照素材库的服务端分页先例),不拉全量回前端过滤。

    `curated=true` 是 B 层口径(有 OSV/补丁/CVSS≥9/人工/项目命中的洞),`false` 是全量索引。
    两个口径共用同一套筛选,所以"精选里没有"的洞切到全部仍搜得到。
    """
    return case_service.list_cases(conn, q=q, severity=severity, id_kind=id_kind, source=source, status=status, completeness=completeness, project_id=project_id, curated=curated, published_from=published_from, published_to=published_to, created_since=created_since, limit=limit, offset=offset)


@router.get("/cases/stats")
def case_stats(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """案例库 KPI 与"上下文收全了没有"的分布。**必须声明在 /cases/{case_id} 之前**,否则会被当成 case_id 解析。"""
    return case_service.case_stats(conn)


@router.get("/cases/{case_id}")
def case_detail(case_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """案例详情:元数据 + 按 context_type 分组的上下文(补丁/漏洞点/数据流/引用)。"""
    item = case_service.case_detail(conn, case_id)
    if not item:
        raise HTTPException(status_code=404, detail="case not found")
    return item


@router.post("/cases")
def create_case(request: CaseCreateRequest, conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    """人工添加案例。两条路径见 CaseCreateRequest.mode 的注释。

    重复添加**不插新行**:auto 走 canonical_id 幂等、manual 走由标题+链接派生的
    `manual:<sha1[:12]>`,再添一次是"重新启用",与威胁域 add_target 的语义一致。
    """
    actor = str(user.get("username") or "")
    mode = str(request.mode or "auto")
    try:
        if mode == "manual":
            title = str(request.title or "").strip()
            if not title:
                raise ValueError("完全手填必须给标题(它参与生成案例主键)")
            canonical_id = case_service.manual_case_id(title, request.source_url)
            id_kind = "custom"
            source = case_service.MANUAL_SOURCE
            status = "active"
        else:
            normalized = case_service.normalize_canonical_id(request.canonical_id)
            if not normalized:
                raise ValueError("认不出这个 id:支持 CVE-xxxx-xxxx / GHSA-xxxx-xxxx-xxxx / OSV-xxxx-n")
            canonical_id, id_kind = normalized["canonical_id"], normalized["id_kind"]
            # 人只给了 id,元数据还没抓 —— 所以 source 记 manual_id(内容的来源),created_by 记人。
            # 采集步富化时会把 source 改成 nvd/osv;而 source='manual_added'(完全手填)的案例
            # 永远不被自动覆盖。
            source = "manual_id"
            status = "pending_fetch"
        context_rows = _case_create_context(request)
        return case_service.upsert_case(
            conn,
            canonical_id=canonical_id,
            id_kind=id_kind,
            title=request.title,
            summary=request.summary,
            severity=request.severity,
            cvss_score=request.cvss_score,
            source_url=request.source_url,
            cwe_ids=_str_list(request.cwe_ids),
            affected_products=_str_list(request.affected_products),
            references=_str_list(request.references),
            source=source,
            status=status,
            actor=actor,
            context_rows=context_rows,
            payload={"added_via": mode},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _case_create_context(request: CaseCreateRequest) -> list[dict]:
    """人工添加时随单附上的上下文:一段代码 + 一条备注 + 若干外链。"""
    rows: list[dict] = []
    if str(request.code or "").strip():
        rows.append({"context_type": "manual_note", "provenance": "manual_added", "label": "人工补充的代码/说明", "content": request.code})
    if str(request.note or "").strip():
        rows.append({"context_type": "manual_note", "provenance": "manual_added", "label": "备注", "content": request.note})
    for url in _str_list(request.references):
        rows.append({"context_type": "reference", "provenance": "manual_added", "source_url": url, "label": url, "content": ""})
    return rows


@router.patch("/cases/{case_id}")
def update_case(case_id: int, request: CaseUpdateRequest, conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    """人工改案例字段(白名单外的键忽略)。"""
    try:
        fields = {key: value for key, value in request.model_dump().items() if value is not None}
        return case_service.update_case(conn, case_id, actor=str(user.get("username") or ""), **fields)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/cases/{case_id}/context")
def add_case_context(case_id: int, request: CaseContextRequest, conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    """人工补一条上下文。**provenance 固定 manual_added** —— 这个入口不接受模型/外部源的来源标注,
    否则一条人写的东西可以被标成 from_osv,前端"事实 vs 推断"的分层就废了。"""
    if not str(request.content or "").strip() and not request.source_url:
        raise HTTPException(status_code=400, detail="内容与链接至少要给一个")
    try:
        inserted = case_service.add_context(
            conn,
            case_id,
            [{
                "context_type": request.context_type,
                "provenance": "manual_added",
                "confidence": request.confidence,
                "repo": request.repo,
                "commit_sha": request.commit_sha,
                "file_path": request.file_path,
                "function_name": request.function_name,
                "start_line": request.start_line,
                "end_line": request.end_line,
                "content": request.content,
                "source_url": request.source_url,
                "label": request.label or f"人工补充({request.context_type})",
            }],
            actor=str(user.get("username") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"case_id": case_id, "inserted": inserted}


@router.get("/case-sources")
def list_case_sources(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """要盯哪些源(生态包 / 单仓 / 指定 id)。P3 的采集步消费这张表。"""
    items = case_service.list_case_sources(conn)
    return {"count": len(items), "items": items}


@router.post("/case-sources")
def add_case_source(request: CaseSourceRequest, conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    try:
        return case_service.add_case_source(
            conn,
            kind=request.kind,
            identifier=request.identifier,
            source_key=request.source_key,
            label=request.label,
            note=request.note,
            created_by=str(user.get("username") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# 与 /manual-keywords/{id}/enable 同一约定:不带 body,用两个路径区分开关(少一个 JSON 就 422 的坑)
@router.post("/case-sources/{source_id}/enable")
def enable_case_source(source_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return case_service.set_case_source_enabled(conn, source_id, True)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/case-sources/{source_id}/disable")
def disable_case_source(source_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return case_service.set_case_source_enabled(conn, source_id, False)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.delete("/case-sources/{source_id}")
def delete_case_source(source_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return {"deleted": case_service.delete_case_source(conn, source_id)}


# ── 项目(P5a):页面上按"项目"看这个项目有哪些已知洞。与「跟踪的漏洞源」不是一回事 ——
#    项目是有名字、可能有多个发布包、以后会有自有公告源的实体;关联证据全部来自已有数据
#    (OSV 的 affected_products、补丁上下文的 repo),P5a 不新增任何外部请求。
#    自动识别包需要联网,所以单独一个 POST /projects/detect,且结果**只是候选**。


@router.get("/projects")
def list_projects(include_disabled: bool = True, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    return project_service.list_projects(conn, include_disabled=include_disabled)


@router.post("/projects/detect")
def detect_project_packages(request: ProjectDetectRequest, conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    """读仓库根目录 manifest,返回候选包。**不落库** —— 由人确认后再 PATCH 进项目。"""
    try:
        result = project_service.detect_packages(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {**result, "url": request.url}


@router.post("/projects")
def create_project(request: ProjectRequest, conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    """新增项目。重复添加 = 合并包并重新启用(与盯源/威胁域 add_target 同语义)。

    建完**立即做一次全量关联**,不让用户等当晚 04:00 的跑批 —— 项目建的当天页面就该有内容。
    """
    try:
        result = project_service.add_project(
            conn,
            url=request.url,
            display_name=request.display_name,
            packages=request.packages,
            tier=request.tier,
            native_sources=request.native_sources,
            created_by=str(user.get("username") or ""),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    result["link"] = project_service.link_project_cases(conn, int(result["project"]["id"]))
    return result


@router.get("/projects/{project_id}")
def get_project(project_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    item = project_service.get_project(conn, project_id)
    if not item:
        raise HTTPException(status_code=404, detail="project not found")
    return item


@router.get("/projects/{project_id}/cases")
def list_project_cases(
    project_id: int,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict:
    """项目详情页的案例时间线。复用 /cases 的筛选与分页,保证两处口径一致。"""
    if not project_service.get_project(conn, project_id):
        raise HTTPException(status_code=404, detail="project not found")
    return case_service.list_cases(conn, project_id=project_id, limit=limit, offset=offset)


@router.patch("/projects/{project_id}")
def update_project(project_id: int, request: ProjectUpdateRequest, conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    """改显示名/包映射/层级。**改了包映射就重扫关联**(包变了,原来关联的案例集合也跟着变)。"""
    fields = {key: value for key, value in request.model_dump().items() if value is not None}
    try:
        result = project_service.update_project(conn, project_id, actor=str(user.get("username") or ""), **fields)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if "packages" in fields:
        result["link"] = project_service.link_project_cases(conn, project_id)
    return result


# 与 /case-sources/{id}/enable 同一约定:不带 body,用两个路径区分开关
@router.post("/projects/{project_id}/enable")
def enable_project(project_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    try:
        return project_service.set_project_enabled(conn, project_id, True)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/projects/{project_id}/disable")
def disable_project(project_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """停用:**案例与关联都保留**,只是不再出现在项目视图、也不再参与每晚跑批。"""
    try:
        return project_service.set_project_enabled(conn, project_id, False)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/projects/{project_id}/link")
def link_project_cases(project_id: int, since: str = "", conn: sqlite3.Connection = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    """手动重扫关联。`since` 传 ISO 时间可只扫最近更新的案例;不传 = 全量(幂等)。"""
    try:
        return project_service.link_project_cases(conn, project_id, since=since)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.delete("/projects/{project_id}")
def delete_project(project_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """删项目(连带关联行)。**案例本身不动** —— 洞是洞,项目只是看它的一个维度。"""
    return {"deleted": project_service.delete_project(conn, project_id)}


# ── 以下 /extractions 与 /knowledge* 接口: 2026-10-16 起**前端页面已撤**(侧栏不再下发
#    「抽取审核」「漏洞知识库」两个入口), 但接口全部保留不删:
#    · /extractions 仍被今日情报页的 30s 轮询用于展示知识候选计数与素材状态, 不能停;
#    · 字段复核三个 POST 只在有人调 reject 时才产生副作用, 撤页后自然归零, 留着便于回滚;
#    · /knowledge/{id}/model-snippet 是撤页后**仍然免费**的抽取质量检查途径(直接看喂给
#      模式合成的片段原文), 出问题时不必重建页面。
#    谁要清理这些接口, 先 grep 前端确认调用方确实归零。


@router.get("/extractions")
def extractions(limit: int = Query(50, ge=1, le=200), conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """知识候选列表(含逐字段复核状态)。页面已撤, 今日情报页仍在轮询。"""
    return vuln_service.extractions(conn, limit=limit)


@router.get("/knowledge")
def knowledge(conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """知识列表(摘要态)。当前无前端调用方, 保留给排查与将来的 API 使用者。"""
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
    """知识条目全量详情。当前无前端调用方(知识抽屉走 /extractions 与 /materials 的数据)。"""
    item = domain_items.detail(conn, DOMAIN, item_id)
    if not item or item.get("item_type") != "knowledge":
        raise HTTPException(status_code=404, detail="knowledge not found")
    return item


@router.get("/knowledge/{item_id}/model-snippet")
def knowledge_model_snippet(item_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict:
    """把该条知识拼成喂给模式合成的片段原文。撤页后检查抽取质量靠它, 不要删。"""
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


# 字段级人工复核(accept/modify/reject): 逐字段确认流程 2026-10-16 下线, 页面已撤。
# 接口保留 —— 只在被调用时写数据, 无人调用即完全惰性, 回滚时不必补代码。


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
