"""能力评测(E1)API —— 与 E0 的「复现跑没跑起来」是两件事。

E0(`capability_eval_levels`)回答"这个工具能不能起来";
E1(这里)回答"在标准样本上判得准不准"。两者都挂在同一个能力条目下, 但口径不同,
页面上必须分开展示 —— 拿 E0 的等级去暗示 E1 的准确率是最容易犯的错。

端点:
  GET  /capabilities/eval/categories          类别 + 各自样本规模
  GET  /capabilities/eval/tools               候选工具(E0 有等级的条目) + 最近一次评测
  GET  /capabilities/eval/tools/{item_id}     单个工具的全部 run + 最近一份报表
  GET  /capabilities/eval/runs/{run_id}       一份 run 的指标 + 逐样本结论
  POST /capabilities/eval/run                 发起一轮评测(执行位未上线前 503)

**不做排序**: 页面上不出现"哪个工具最好"。样本只有 20 对, 区间本身就有 ±0.2 宽
(契约 §6), 排序会把噪声当成结论。
"""
from __future__ import annotations

import os
import sqlite3
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ai4sec_platform.app.dependencies import current_user, get_db
from ai4sec_platform.domains.capabilities.eval import store

router = APIRouter(prefix="/capabilities/eval", tags=["capability-eval"])

# C1–C4(评测容器 / runner / 预算闸)上线后置 True。
# 在那之前 POST /run 直接 503: 建出来的 run 没人执行, 只会变成一条永远 running 的僵尸行。
#
# 2026-11-03: 改成读环境变量(默认仍 False)。执行位是 `--profile eval` 单独起的,
# 打开时机与镜像版本无关 —— 若写死在代码里, 每翻一次开关都要重建镜像并重启全栈,
# 而重启窗口本身是有代价的(要避夜跑批、要查 running 的复现任务)。默认不变时
# 行为与写死 False 完全一致, 所以这次改动不影响任何既有路径。
RUNNER_READY = os.environ.get("EVAL_RUNNER_READY", "").strip().lower() in {"1", "true", "yes", "on"}

# 报表里上页面的那几个数。全部来自 score.py 的 aggregate, 不在这里二次计算。
METRIC_KEYS = ("locate_rate", "strict_locate_rate", "false_positive_rate", "balanced_accuracy")


class StartEvalRequest(BaseModel):
    item_id: int = Field(..., ge=1)
    category: str | None = None
    repeats: int = Field(3, ge=1, le=10)
    budget: dict[str, Any] = Field(default_factory=dict)


def _headline(report: dict[str, Any] | None) -> dict[str, Any] | None:
    """把 aggregate 压成页面能直接用的形状。缺的指标给 null, 不补 0。"""
    if not report:
        return None
    agg = report.get("aggregate") or {}
    out: dict[str, Any] = {
        "n_samples": report.get("n_samples"),
        # 真正进分母的是 n_samples - n_excluded。两个数一起给, 页面上才画不出
        # "20 个样本全部参与打分"这种错觉(D4-5)。
        "n_excluded": report.get("n_excluded"),
        "excluded_reasons": report.get("excluded_reasons") or {},
        "window": report.get("window"),
        "adaptation_verdict": report.get("adaptation_verdict"),
        "repeats": len(report.get("repeats") or []),
    }
    for key in METRIC_KEYS:
        entry = agg.get(key) or {}
        out[key] = {
            "value": entry.get("median"),
            "ci95": entry.get("ci95_of_median_repeat"),
            "values": entry.get("values") or [],
            "identical": entry.get("identical"),
        }
    return out


def _latest_run(conn: sqlite3.Connection, item_id: int, category: str) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT id FROM capability_eval_runs WHERE item_id=? AND category=?"
        " ORDER BY started_at DESC, id DESC LIMIT 1", (item_id, category),
    ).fetchone()
    if row is None:
        return None
    run = store.get_run(conn, int(row["id"]))
    if run is None:
        return None
    return {
        "run_id": run["id"], "status": run["status"], "tool_version": run["tool_version"],
        "started_at": run["started_at"], "finished_at": run["finished_at"],
        "repeats": run["repeats"], "failure_reason": run["failure_reason"],
        "metrics": _headline(run.get("report")), "caveats": run.get("caveats") or "",
    }


@router.get("/categories")
def categories(conn: sqlite3.Connection = Depends(get_db)) -> dict[str, Any]:
    return {"items": store.list_categories(conn), "runner_ready": RUNNER_READY}


@router.get("/tools")
def tools(
    category: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    """候选工具 = capability_eval_levels 里的条目(E1 只对有 E0 等级的条目开放)。

    `latest_run` 为 null 表示**尚未评测**, 不是"评测失败"。页面必须分开写,
    否则"没被评"会被读成"评了不行"(PRD §13 的边界)。

    **只出 Web 条目**(2026-11-02 拍板: E1 本期只覆盖 Web, 非 Web 183 条不评)。
    判据与复现侧同一个口径: 只有 `payload.is_web` **明确为 false** 才算非 Web;
    没有这个键 = 尚未分类, 不因此把它挡掉(见 `assessments.is_non_web_blocked`)。
    不在这里过滤的话, 页面上会列出"按口径不该被评"的工具 —— 边界说明就成了假话。
    """
    category = category or store.CATEGORY_CLASS1
    if category not in {c["id"] for c in store.CATEGORIES}:
        raise HTTPException(status_code=400, detail=f"未知类别: {category}")

    rows = conn.execute(
        "SELECT l.item_id, l.e0_level, l.e0_method, l.e0_source, l.e0_verified_at,"
        " d.title, d.status"
        " FROM capability_eval_levels l JOIN domain_items d ON d.id = l.item_id"
        " WHERE d.domain='capabilities'"
        " AND COALESCE(json_extract(d.payload_json, '$.is_web'), 1) <> 0"
        " ORDER BY l.e0_level DESC, l.item_id DESC LIMIT ?", (limit,),
    ).fetchall()

    items = []
    for row in rows:
        items.append({
            "item_id": row["item_id"], "title": row["title"], "status": row["status"],
            "e0": {"level": row["e0_level"], "method": row["e0_method"],
                   "source": row["e0_source"], "verified_at": row["e0_verified_at"]},
            "latest_run": _latest_run(conn, int(row["item_id"]), category),
        })
    return {"category": category, "total": len(items), "items": items}


@router.get("/tools/{item_id}")
def tool_detail(
    item_id: int,
    category: str | None = Query(None),
    conn: sqlite3.Connection = Depends(get_db),
) -> dict[str, Any]:
    category = category or store.CATEGORY_CLASS1
    item = conn.execute(
        "SELECT id, title, status FROM domain_items WHERE domain='capabilities' AND id=?",
        (item_id,),
    ).fetchone()
    if item is None:
        raise HTTPException(status_code=404, detail=f"能力条目不存在: {item_id}")

    level = conn.execute(
        "SELECT e0_level, e0_method, e0_source, e0_verified_at, e0_evidence_json"
        " FROM capability_eval_levels WHERE item_id=?", (item_id,),
    ).fetchone()

    runs = store.list_runs(conn, item_id=item_id, category=category, limit=20)
    latest_report = None
    results: list[dict[str, Any]] = []
    if runs:
        full = store.get_run(conn, int(runs[0]["id"]))
        latest_report = full.get("report") if full else None
        results = store.get_results(conn, int(runs[0]["id"]))

    return {
        "item_id": item_id,
        "title": item["title"],
        "status": item["status"],
        "category": category,
        "e0": None if level is None else {
            "level": level["e0_level"], "method": level["e0_method"],
            "source": level["e0_source"], "verified_at": level["e0_verified_at"],
        },
        "runs": [dict(r) for r in runs],
        "latest": None if not runs else {
            "run": store.get_run(conn, int(runs[0]["id"])),
            "metrics": _headline(latest_report),
            "results": results,
        },
        # 页面上这块**不可折叠**: 一份没有边界说明的准确率, 读者一定会外推
        "cannot_answer": [
            "单文件任务: 测不出跨文件污点追踪。",
            "真实仓库的噪声(vendor/测试/生成代码)不在样本里, 真实误报率会更高。",
            "判据含 LLM 成分: 漏洞点是模型从补丁里指的, 规则只校验范围不校验唯一性。",
            "样本会过期(R12): 与模型知识截止日重叠时, 命中可能只是见过这个洞。",
        ],
    }


@router.get("/runs/{run_id}")
def run_detail(run_id: int, conn: sqlite3.Connection = Depends(get_db)) -> dict[str, Any]:
    run = store.get_run(conn, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"评测 run 不存在: {run_id}")
    return {
        "run": run,
        "metrics": _headline(run.get("report")),
        "results": store.get_results(conn, run_id),
    }


@router.post("/run")
def start_run(
    body: StartEvalRequest,
    conn: sqlite3.Connection = Depends(get_db),
    user: dict = Depends(current_user),
) -> dict[str, Any]:
    """发起一轮评测。

    执行位没上线时**直接拒绝**, 不建 run —— 建了没人跑的行会被当成"评测卡住了",
    实际上连开始都没开始。等 C1–C4 上线把 RUNNER_READY 打开。
    """
    if not RUNNER_READY:
        raise HTTPException(
            status_code=503,
            detail="评测执行位(容器/runner/预算闸)尚未上线, 现在发起不会被执行, 故不创建 run。",
        )
    level = conn.execute("SELECT e0_level FROM capability_eval_levels WHERE item_id=?",
                         (body.item_id,)).fetchone()
    if level is None:
        raise HTTPException(status_code=409, detail="该条目还没有 E0 等级, 不做 E1 评测")
    # 与 /tools 同一个口径: 本期 E1 只覆盖 Web 条目。列表里看不到、却能被直接发起,
    # 等于留了一条绕过边界说明的路。
    is_web = conn.execute(
        "SELECT COALESCE(json_extract(payload_json, '$.is_web'), 1) FROM domain_items WHERE id=?",
        (body.item_id,)).fetchone()
    if is_web is not None and int(is_web[0]) == 0:
        raise HTTPException(status_code=409, detail="该条目是非 Web 项目, 本期 E1 只覆盖 Web 条目")
    category = body.category or store.CATEGORY_CLASS1
    n_samples = conn.execute(
        "SELECT COUNT(*) FROM capability_eval_samples WHERE category=?", (category,)).fetchone()[0]
    if not n_samples:
        raise HTTPException(status_code=409, detail="该类别还没有样本, 先落库数据集")

    run_id = store.create_run(
        conn, item_id=body.item_id, category=category, repeats=body.repeats,
        budget={**body.budget, "requested_by": user.get("username", "anonymous")},
    )
    return {"run_id": run_id, "status": "running", "n_samples": n_samples}
