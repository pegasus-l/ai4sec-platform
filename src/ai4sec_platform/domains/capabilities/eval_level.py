"""能力库 E0 有效性等级: 由**平台**按复现报告里的证据算等级, 被测 agent 不自评。

阶梯(与 PRD 一致):
    L0 未验      —— 没有可用报告, 或报告里连构建证据都没有
    L1 构建      —— build.command + build.exit_code == 0
    L2 启动      —— 有 start_command/web_started, 且 verify 写了一次真实探测的结果
    L3 冒烟      —— 平台页面自检通过(有真实内容) 或 真跑了一套测试且全通过
    L4 核心工作流 —— core_workflow.mode=real + 至少一条能独立复核的 evidence

两种口径(写在 e0_method):
    contract —— 2026-10-31 起提示词要求的结构化证据(build/tests/core_workflow.evidence)。
                **阶梯严格累积**: 低一级没证据, 高一级不成立。
    backfill —— 历史报告(没有 build 字段)。只能按「关键步骤」推断 L1, 且**封顶 L3**:
                旧报告的核心工作流证据是 agent 的自由叙述, 够不上 L4 要求的可复核证据。
                缺证据的每一级都写进 caveats, 页面上要能看见。

为什么单独建表而不是加列/塞 payload: 列表页要按能力条目一次取全部等级, 而
domain_items.payload_json 已经是列表体积的主要来源(见 2026-10-17 那次 129MB 事故),
塞进去会重写全表; 这张表一行几十字节, 还能 DROP TABLE 一键回滚(与 threat_repo_filters 同思路)。
"""
from __future__ import annotations

import ast
import json
from datetime import datetime, timezone
from typing import Any

LEVEL_NAMES = {0: "未验", 1: "构建", 2: "启动", 3: "冒烟", 4: "核心工作流"}
METHOD_LABELS = {"contract": "当前口径", "backfill": "历史口径"}

_BUILD_HINTS = ("install", "build", "compile", "make", "pip ", "pip3", "pnpm", "npm ", "yarn",
                "cargo", "go build", "go mod", "mvn", "gradle", "setup.py", "poetry", "uv ",
                "安装", "依赖", "编译", "构建")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _truthy(value: Any) -> bool:
    """报告里的布尔字段可能是真的 bool, 也可能是 "True"/"false" 这类字符串(旧模型输出如此)。"""
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in ("true", "1", "yes", "y", "done", "ok")


def _as_list(value: Any) -> list[Any]:
    """evidence 有时是 list, 有时是被模型写成字符串的 JSON/Python-repr —— 两种都要认。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text[0] in "[(":
            parsed = None
            try:
                parsed = json.loads(text)
            except Exception:  # noqa: BLE001 - 退回 Python 字面量(单引号的 repr)
                try:
                    parsed = ast.literal_eval(text)
                except Exception:  # noqa: BLE001
                    parsed = None
            if isinstance(parsed, (list, tuple)):
                return list(parsed)
        return [value]
    return [value]


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _short(value: Any, limit: int = 120) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _find_build_step(steps: Any) -> dict | None:
    """历史报告没有 build 字段, 只能从「关键步骤」里找一条成功的安装/构建步骤。"""
    for step in _as_list(steps):
        if not isinstance(step, dict) or not _truthy(step.get("ok")):
            continue
        blob = f"{step.get('cmd') or ''} {step.get('note') or ''}".lower()
        if any(h in blob for h in _BUILD_HINTS):
            return step
    return None


def compute_e0_level(report: dict[str, Any] | None) -> dict[str, Any] | None:
    """算 E0 等级。报告不可用(空/僵尸)时返回 None —— 调用方不要落行, 页面按「未验」显示。"""
    if not isinstance(report, dict) or not report:
        return None
    if not (report.get("status") or report.get("core_workflow") or "web_started" in report):
        return None

    build = report.get("build") if isinstance(report.get("build"), dict) else {}
    contract = bool(str(build.get("command") or "").strip())
    method = "contract" if contract else "backfill"
    caveats: list[str] = []
    rungs: list[dict[str, Any]] = []

    # ---- L1 构建 ----
    if contract:
        exit_code = build.get("exit_code")
        l1 = _int(exit_code) == 0
        detail = f"{_short(build.get('command'))} · exit {exit_code if exit_code is not None else '未给出'}"
        if build.get("artifact"):
            detail += f" · 产物 {_short(build.get('artifact'), 80)}"
        if exit_code is None:
            caveats.append("构建: 报告给了命令但没给退出码, 按未通过处理")
        source = "agent 报告"
    else:
        step = _find_build_step(report.get("steps"))
        if step is not None:
            l1 = True
            detail = f"按关键步骤推断: {_short(step.get('cmd') or step.get('note'))}"
            caveats.append("构建: 旧版报告没有 build 字段, L1 由「关键步骤」推断, 不是平台复核过的退出码")
            source = "agent 报告(推断)"
        else:
            l1 = None
            detail = "报告没有构建证据"
            source = ""
            caveats.append("构建: 旧版报告没有构建证据")
    rungs.append({"level": 1, "name": LEVEL_NAMES[1], "ok": l1, "source": source, "detail": detail})

    # ---- L2 启动 ----
    web_started = _truthy(report.get("web_started"))
    start_cmd = str(report.get("start_command") or "").strip()
    verify = report.get("verify")
    verify_text = _short("; ".join(str(v) for v in verify[:3])) if isinstance(verify, list) else _short(verify)
    l2 = bool(verify_text) and (web_started or bool(start_cmd))
    rungs.append({
        "level": 2, "name": LEVEL_NAMES[2], "ok": l2, "source": "agent 报告",
        "detail": f"web_started={web_started} · {verify_text or '没有探测结果(verify 为空)'}",
    })
    if not l2 and (web_started or start_cmd):
        caveats.append("启动: 声称启动了, 但 verify 里没有可复核的探测结果")

    # ---- L3 冒烟 ----
    pc = report.get("page_check") if isinstance(report.get("page_check"), dict) else {}
    page_failed = pc.get("ok") is False
    try:
        visible_chars = int(pc.get("visible_chars") or 0)
    except (TypeError, ValueError):
        visible_chars = 0
    page_strong = pc.get("ok") is True and visible_chars >= 40
    tests = report.get("tests") if isinstance(report.get("tests"), dict) else {}
    totals = tests.get("totals") if isinstance(tests.get("totals"), dict) else {}
    passed, failed = _int(totals.get("passed")), _int(totals.get("failed"))
    tests_ok = (str(tests.get("result") or "").strip().lower() in ("pass", "passed", "success")
                and passed > 0 and failed == 0)
    if page_failed:
        l3 = False
        detail = "平台页面自检没通过: " + "; ".join(str(i) for i in _as_list(pc.get("issues"))[:2])
    elif tests_ok:
        l3 = True
        detail = f"测试通过 {passed}/{passed + max(failed, 0)}"
        if tests.get("framework"):
            detail += f" ({tests.get('framework')})"
        if page_strong:
            detail += f"; 平台页面自检通过(可见正文 {visible_chars} 字符)"
    elif page_strong:
        l3 = True
        detail = f"平台页面自检通过(可见正文 {visible_chars} 字符); 仓库没有跑测试"
        caveats.append("冒烟: 只有平台页面自检, 没有测试结果")
    else:
        l3 = False
        detail = "既没有跑通的测试, 也没有平台页面自检"
        if pc.get("ok") is True:
            caveats.append(f"冒烟: 页面自检虽然返回 ok, 但正文只有 {visible_chars} 字符, 不足以证明页面可用")
    rungs.append({"level": 3, "name": LEVEL_NAMES[3], "ok": l3, "source": "平台自检 + agent 报告", "detail": detail})

    # ---- L4 核心工作流 ----
    cw = report.get("core_workflow") if isinstance(report.get("core_workflow"), dict) else {}
    mode = str(cw.get("mode") or "").strip().lower()
    evidence = [e for e in _as_list(cw.get("evidence")) if str(e).strip()]
    strong = [e for e in evidence if len(str(e)) >= 20]
    l4 = mode == "real" and _truthy(cw.get("verified")) and bool(strong)
    if l4:
        detail = f"真实跑通核心链路, {len(strong)} 条可复核证据"
    elif cw:
        detail = f"mode={mode or '未写'} · verified={_truthy(cw.get('verified'))} · 证据 {len(strong)} 条"
        if mode != "real":
            caveats.append("核心工作流: 用的不是真实数据(mode≠real)")
        elif not strong:
            caveats.append("核心工作流: 声称验证过, 但没有一条能独立复核的证据")
    else:
        detail = "报告没有 core_workflow"
    rungs.append({"level": 4, "name": LEVEL_NAMES[4], "ok": l4, "source": "agent 报告", "detail": detail})

    # ---- 定级 ----
    if contract:
        level = 0
        for rung in rungs:
            if rung["ok"] is True:
                level = rung["level"]
            else:
                break
    else:
        # 历史口径不认 L4: 旧报告的 core_workflow.evidence 是 agent 的自由叙述, 没有「命令+真实响应片段」
        # 那种可复核形态, 谁也没法拿它复核。所以 L4 这一级在历史口径里直接不计, 而不是算出来再压到 3
        # —— 压到 3 会出现「等级 L3、L3 那一级却是 ✗」的自相矛盾。
        ok_levels = [r["level"] for r in rungs if r["ok"] is True and r["level"] <= 3]
        level = max(ok_levels) if ok_levels else 0
        if l4:
            caveats.append("历史口径不计 L4: 旧报告的核心工作流证据是 agent 自由叙述, 要拿 L4 需按当前提示词重跑")

    missing = [r["name"] for r in rungs if r["ok"] is not True]
    # 报告里到底有没有结构化证据(哪怕结论是失败的)。全空 = 超时兜底生成的那种报告,
    # 它算出的 L0 不代表项目退化, 不该覆盖已有的结论; 而「构建 exit 2」这种 L0 是有证据的结论。
    structured = bool(
        contract
        or str(report.get("verify") or "").strip()
        or bool(tests)
        or bool(cw)
    )
    return {
        "e0_level": level,
        "e0_label": LEVEL_NAMES.get(level, ""),
        "e0_method": method,
        "rungs": rungs,
        "missing": missing,
        "caveats": caveats,
        "structured": structured,
    }


CREATE_SQL = """
CREATE TABLE IF NOT EXISTS capability_eval_levels (
    item_id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL DEFAULT 'capabilities',
    e0_level INTEGER NOT NULL DEFAULT 0,
    e0_method TEXT NOT NULL DEFAULT '',
    e0_evidence_json TEXT NOT NULL DEFAULT '{}',
    e0_verified_at TEXT NOT NULL DEFAULT '',
    source_task_id INTEGER,
    computed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cap_eval_level ON capability_eval_levels(e0_level);
"""


def ensure_table(conn) -> None:
    """与 db/models 的 SCHEMA_SQL 同源, 重复执行安全(init_db 每次 get_db 都跑 CREATE IF NOT EXISTS)。"""
    conn.executescript(CREATE_SQL)


def record_eval_level(conn, *, item_id: int, task_id: int | None, report: dict[str, Any] | None,
                      computed_at: str | None = None) -> dict[str, Any] | None:
    """算完就落库(一个能力条目一行, 新的覆盖旧的)。报告不可用返回 None, 不落行。"""
    result = compute_e0_level(report)
    if result is None:
        return None
    if result["e0_level"] == 0 and not result.get("structured"):
        # 没有证据的一轮不覆盖已有证据的结论: L0 的定义就是「这一轮没验出来」, 拿它把 L2 洗成
        # 未验会让一次超时/环境抖动看起来像项目退化。有证据的新结论(哪怕也是 0)照常覆盖。
        try:
            existing = conn.execute(
                "SELECT e0_level FROM capability_eval_levels WHERE item_id = ?", (int(item_id),)
            ).fetchone()
        except Exception:  # noqa: BLE001 - 表还没建时按「没有旧结论」处理
            existing = None
        if existing and int(existing[0]) > 0:
            return result
    ts = computed_at or _utc_now()
    conn.execute(
        "INSERT INTO capability_eval_levels"
        " (item_id, domain, e0_level, e0_method, e0_evidence_json, e0_verified_at, source_task_id, computed_at)"
        " VALUES (?, 'capabilities', ?, ?, ?, ?, ?, ?)"
        " ON CONFLICT(item_id) DO UPDATE SET"
        "  e0_level=excluded.e0_level, e0_method=excluded.e0_method,"
        "  e0_evidence_json=excluded.e0_evidence_json, e0_verified_at=excluded.e0_verified_at,"
        "  source_task_id=excluded.source_task_id, computed_at=excluded.computed_at",
        (
            int(item_id), int(result["e0_level"]), result["e0_method"],
            json.dumps(result, ensure_ascii=False), ts, int(task_id) if task_id else None, ts,
        ),
    )
    return result


def fetch_levels(conn, item_ids: list[int]) -> dict[int, dict[str, Any]]:
    """批量取等级(列表页用)。返回 {item_id: {e0_level, e0_method, e0_verified_at, source_task_id}}。"""
    ids = sorted({int(i) for i in item_ids if i})
    out: dict[int, dict[str, Any]] = {}
    if not ids:
        return out
    for start in range(0, len(ids), 500):
        chunk = ids[start:start + 500]
        marks = ",".join("?" * len(chunk))
        try:
            rows = conn.execute(
                "SELECT item_id, e0_level, e0_method, e0_verified_at, source_task_id"
                f" FROM capability_eval_levels WHERE item_id IN ({marks})",
                chunk,
            ).fetchall()
        except Exception:  # noqa: BLE001 - 表还没建(首次部署)时列表页不能因此 500
            return out
        for row in rows:
            out[int(row[0])] = {
                "e0_level": int(row[1]),
                "e0_label": LEVEL_NAMES.get(int(row[1]), ""),
                "e0_method": str(row[2] or ""),
                "e0_verified_at": str(row[3] or ""),
                "source_task_id": int(row[4]) if row[4] else None,
            }
    return out


def fetch_evidence(conn, item_id: int) -> dict[str, Any] | None:
    """取单个条目的完整证据链(详情抽屉用)。"""
    try:
        row = conn.execute(
            "SELECT e0_level, e0_method, e0_evidence_json, e0_verified_at, source_task_id"
            " FROM capability_eval_levels WHERE item_id = ?", (int(item_id),),
        ).fetchone()
    except Exception:  # noqa: BLE001
        return None
    if not row:
        return None
    try:
        payload = json.loads(row[2] or "{}")
    except Exception:  # noqa: BLE001
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    payload.update({
        "e0_level": int(row[0]),
        "e0_label": LEVEL_NAMES.get(int(row[0]), ""),
        "e0_method": str(row[1] or ""),
        "e0_method_label": METHOD_LABELS.get(str(row[1] or ""), ""),
        "e0_verified_at": str(row[3] or ""),
        "source_task_id": int(row[4]) if row[4] else None,
    })
    return payload


def _loads(raw: Any) -> dict[str, Any] | None:
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw or "{}")
    except Exception:  # noqa: BLE001
        return None
    return data if isinstance(data, dict) else None


def latest_usable_task(conn, item_id: int) -> dict[str, Any] | None:
    """某条目最近一条**报告可用**的复现任务(僵尸行 report_json='{}' 不算)。"""
    rows = conn.execute(
        "SELECT id, status, report_json, finished_at FROM capability_repro_tasks"
        " WHERE item_id = ? ORDER BY id DESC", (int(item_id),),
    ).fetchall()
    for row in rows:
        report = _loads(row[2])
        if compute_e0_level(report) is not None:
            return {"id": int(row[0]), "status": str(row[1] or ""),
                    "report": report, "finished_at": str(row[3] or "")}
    return None


def backfill(conn, *, dry_run: bool = False, limit: int | None = None) -> dict[str, Any]:
    """历史回填: 每条能力取最近一条可用报告, 算等级并落库。幂等(重复跑结果一致)。

    dry_run 不建表也不写库 —— 这样可以直接挂在只读连接(mode=ro)上算一遍看结果。
    """
    if not dry_run:
        ensure_table(conn)
    rows = conn.execute(
        "SELECT DISTINCT t.item_id, d.status,"
        " json_extract(d.payload_json, '$.repro_status')"
        " FROM capability_repro_tasks t JOIN domain_items d ON d.id = t.item_id"
        " WHERE d.domain = 'capabilities'"
    ).fetchall()
    stats = {"items": 0, "written": 0, "skipped_not_supported": 0, "skipped_no_report": 0,
             "by_level": {}, "by_method": {}, "items_detail": []}
    targets = rows[:limit] if limit else rows
    for item_id, _item_status, repro_status in targets:
        stats["items"] += 1
        if str(repro_status or "") == "not_supported":
            stats["skipped_not_supported"] += 1
            continue
        task = latest_usable_task(conn, int(item_id))
        if task is None:
            stats["skipped_no_report"] += 1
            continue
        result = compute_e0_level(task["report"])
        if result is None:
            stats["skipped_no_report"] += 1
            continue
        level, method = result["e0_level"], result["e0_method"]
        stats["by_level"][str(level)] = stats["by_level"].get(str(level), 0) + 1
        stats["by_method"][method] = stats["by_method"].get(method, 0) + 1
        stats["items_detail"].append({
            "item_id": int(item_id), "task_id": task["id"], "status": task["status"],
            "e0_level": level, "e0_label": result["e0_label"], "e0_method": method,
            "missing": result["missing"],
        })
        if not dry_run:
            record_eval_level(conn, item_id=int(item_id), task_id=task["id"], report=task["report"])
            stats["written"] += 1
    if not dry_run:
        conn.commit()
    return stats


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sqlite3

    from ai4sec_platform.db.session import connect

    parser = argparse.ArgumentParser(description="能力库 E0 等级回填(默认 dry-run)")
    parser.add_argument("--apply", action="store_true", help="真的写库(默认只统计)")
    parser.add_argument("--limit", type=int, default=None, help="只处理前 N 条(调试用)")
    args = parser.parse_args(argv)
    conn = connect()
    conn.row_factory = sqlite3.Row
    try:
        stats = backfill(conn, dry_run=not args.apply, limit=args.limit)
    finally:
        conn.close()
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
