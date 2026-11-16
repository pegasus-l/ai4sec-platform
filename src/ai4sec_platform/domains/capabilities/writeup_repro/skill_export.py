"""把复现产物渲染成 Claude Code skill 的 markdown。

为什么渲染放在**平台**而不是脚本里
====================================

「产物」页签要给用户看"这条任务会导出成哪个文件、里面写了什么"。如果页面自己拼一份、
导出脚本再拼一份, 两份迟早不一致 —— 而它们描述的是**同一个文件**。所以渲染只此一处:
页面调 ``GET /tasks/{id}/skill`` 拿这里的输出, 同步脚本也从这里取(它 ssh 进容器执行
``export_bundle``), 两边看到的是同一串字符。

两层口径(写进每个文件的开头, 不由读者猜)
=========================================

=====================================  ==========================================  ============
目录                                   来源                                        可信度
=====================================  ==========================================  ============
``references/verified/``               真跑通的复现报告第 6/7 节 + 规则校验         **验证过**
``references/catalog/``                知识条目按 CWE 归纳, **没跑过**               **线索**
=====================================  ==========================================  ============

catalog 里的 ``confidence`` 是模型归纳时的自评, **不是准确率**; 引用它必须连
``coverage_note``(样本几条、哪部分待复核)一起说。这条不写死在这里, 那个库三个月后
就会变成一个自信的胡说库。
"""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from ai4sec_platform.domains.capabilities.writeup_repro import recipes as recipes_module
from ai4sec_platform.domains.capabilities.writeup_repro import report as report_module

#: skill 目录名(生成端与页面共用; 真实落盘根目录由同步脚本决定)。
SKILL_NAME = "ai4sec-vuln-audit"


def now() -> str:
    return f"{datetime.now(timezone.utc):%Y-%m-%dT%H:%M:%SZ}"


def _one_line(value: Any, limit: int = 160) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _bullets(items: Any) -> str:
    if not items:
        return "（无）"
    if isinstance(items, str):
        return items
    return "\n".join(f"- {item}" for item in items)


def verified_path(material_id: Any) -> str:
    return f"references/verified/material-{int(material_id)}.md"


def case_path(task_id: Any, material_id: Any) -> str:
    return f"references/cases/task-{int(task_id)}-material-{int(material_id)}.md"


def catalog_path(cwe: str) -> str:
    return f"references/catalog/{str(cwe).lower()}.md"


# ---------------------------------------------------------------- 材料

def _material(conn: sqlite3.Connection, material_id: int) -> dict[str, Any]:
    conn.row_factory = conn.row_factory or sqlite3.Row
    row = conn.execute(
        "SELECT id, title, source_url FROM domain_items"
        " WHERE id = ? AND domain = 'vulnerabilities' AND item_type = 'material'",
        (int(material_id),),
    ).fetchone()
    if row is None:
        return {"id": int(material_id), "title": "", "url": ""}
    return {"id": int(row["id"]), "title": row["title"] or "", "url": row["source_url"] or ""}


# ---------------------------------------------------------------- 已验证规律

def render_verified(
    pattern: dict[str, Any],
    recipe: dict[str, Any] | None,
    report: dict[str, Any] | None,
    material: dict[str, Any],
) -> str:
    material_id = pattern.get("material_id")
    title = material.get("title") or f"素材 #{material_id}"
    lines = [
        f"# 已验证规律: {title}",
        "",
        "> **这条是真跑过的。** 来自复现任务 "
        f"#{pattern.get('report_id')} 的报告第 6/7 节, 经规则校验后入库; "
        f"provenance={pattern.get('provenance')}, 置信度字段={pattern.get('confidence')}"
        "(None = 平台未打分, 不是 0)。",
        "",
        "## 不变量(被破坏的那条)",
        str(pattern.get("invariant") or "（无）"),
        "",
        "## 代码特征(什么样的代码有这个问题)",
        str(pattern.get("code_feature") or "（无）"),
        "",
        "## 审计入口(从哪进、传什么、观察什么)",
        str(pattern.get("audit_entry") or "（无）"),
        "",
        "## 判别点(为什么容易漏, 怎么区分误报)",
        str(pattern.get("discriminator") or "（无）"),
        "",
        f"## 指纹\n`{_one_line(pattern.get('fingerprint'), 400)}`",
        "",
    ]
    body = (recipe or {}).get("recipe_json") or {}
    if isinstance(body, str):
        try:
            body = json.loads(body or "{}")
        except ValueError:
            body = {}
    if body:
        lines += ["## 实测可复现路径(来自配方)", ""]
        for section, label in (("acquire", "取得目标"), ("setup", "准备环境"),
                               ("trigger", "触发"), ("probe", "判定")):
            steps = body.get(section)
            if not steps:
                continue
            if isinstance(steps, dict):
                steps = [steps]
            lines.append(f"**{label}**")
            for step in steps:
                suffix = f"  exit={step.get('exit_code')}" if step.get("exit_code") is not None else ""
                lines.append(f"- `{_one_line(step.get('cmd'), 300)}`{suffix}")
            lines.append("")
        probe = body.get("probe") or {}
        if probe.get("success_signal"):
            lines += [f"**成功判据**: `{_one_line(probe['success_signal'], 300)}`", ""]
    if report:
        observed = report.get("observed_json") or {}
        claim = report.get("claim_json") or {}
        lines += [
            "## 这次复现的关键事实",
            "",
            f"- 结论: `{report.get('verdict')}`",
            f"- 原文声称: {_one_line(claim.get('claim'), 400)}",
            f"- 实测命中: {observed.get('matched')} / 判据 `{_one_line(observed.get('success_signal'), 160)}`",
        ]
        caveats = report.get("caveats") or []
        if caveats:
            lines += ["", "**这次复现的 caveats(结论要带着它们一起说)**", ""]
            lines += [f"- {c}" for c in caveats]
        lines += ["", f"完整报告见 `{case_path(report.get('task_id'), material_id)}`。"]
    lines += ["", f"来源: 素材 #{material_id}" + (f" · {title}" if title else "")]
    return "\n".join(lines)


# ---------------------------------------------------------------- 复现案例

def render_case(report: dict[str, Any], material: dict[str, Any]) -> str:
    material_id = report.get("material_id")
    title = material.get("title") or f"素材 #{material_id}"
    claim = report.get("claim_json") or {}
    observed = report.get("observed_json") or {}
    attribution = report.get("attribution_json") or {}
    root = report.get("root_cause_json") or {}
    pattern = report.get("pattern_json") or {}
    evidence = report.get("evidence_json") or {}
    lines = [
        f"# 复现案例: {title}",
        "",
        f"> 任务 #{report.get('task_id')} · 素材 #{material_id} · 结论 `{report.get('verdict')}` · "
        f"{report.get('generated_by')} 生成 · {report.get('created_at')}",
        "",
        "## 1 结论",
        f"`{report.get('verdict')}`"
        + (f" / {report.get('failure_reason')}" if report.get("failure_reason") else ""),
        "",
        "## 2 原文声称(author)",
        str(claim.get("claim") or "（无）"),
        "",
        f"> 原文引用: {_one_line(claim.get('claim_quote'), 400)}",
        "",
        "## 3 实际执行(平台只认证据包里的真实命令)",
        "",
    ]
    commands = (evidence.get("section") or {}).get("commands") or []
    if commands:
        for cmd in commands:
            text = str(cmd.get("cmd") or "")
            if "\n" in text:
                # 多行命令(比如 heredoc 写 PoC)压成一行就没法照着跑了, 原样保留。
                lines += [f"**{cmd.get('index')}** (exit={cmd.get('exit_code')})", "",
                          "```bash", text.rstrip()[:4000], "```", ""]
            else:
                lines.append(f"{cmd.get('index')}. `{text}`  exit={cmd.get('exit_code')}")
    else:
        lines.append("（证据包里没有命令记录）")
    lines += [
        "",
        "## 4 实测现象",
        f"- probe 找到: {observed.get('probe_found')} / 判据: "
        f"`{_one_line(observed.get('success_signal'), 200)}` / 命中: {observed.get('matched')}",
        f"- 命令: `{_one_line(observed.get('cmd'), 300)}`",
        "",
        "## 5 归因",
        f"- 责任方: {attribution.get('side') or '（成功, 无需归因）'} / "
        f"{_one_line(attribution.get('reason'), 300)}",
        "",
        "## 6 漏洞根因",
        f"- 位置: `{_one_line(root.get('location'), 300)}`",
        f"- 不变量: {root.get('invariant')}",
        "",
        "## 7 发现规律",
        f"- 泛化边界: {pattern.get('generalization')} / 指纹: "
        f"`{_one_line(pattern.get('fingerprint'), 300)}`",
        f"- 代码特征: {pattern.get('code_feature')}",
        "",
        "## 8 限制(caveats)",
    ]
    lines += [f"- {c}" for c in (report.get("caveats") or ["（无）"])]
    return "\n".join(lines)


# ---------------------------------------------------------------- CWE 级模式(线索)

def render_catalog(payload: dict[str, Any]) -> str:
    cwe_ids = payload.get("cwe_ids") or []
    cwe = str(cwe_ids[0]).upper() if cwe_ids else str(payload.get("cluster_key") or "").replace("cwe:", "")
    lines = [
        f"# {cwe} · {payload.get('pattern_name') or '(无标题)'}",
        "",
        "> **线索, 未经本机复现验证。** 来源: 知识条目按 CWE 聚类归纳; "
        f"样本 {payload.get('member_count')} 条; 模型自评 confidence={payload.get('confidence')}"
        "(不是准确率)。",
        "",
        "## 一句话", str(payload.get("pattern_summary") or "（无）"),
        "",
        "## 抽象根因", str(payload.get("abstract_root_cause") or "（无）"),
        "",
        "## 常见触发形态", str(payload.get("common_trigger") or "（无）"),
        "",
        "## 检测指引(怎么找)", str(payload.get("detection_guidance") or "（无）"),
        "",
        "## 代码检索关键词", _bullets(payload.get("code_search_keywords")),
        "",
        "## 常见利用原语", _bullets(payload.get("common_exploit_primitives")),
        "",
        "## 修复范式", str(payload.get("fix_paradigm") or "（无）"),
        "",
        "## 代表案例(真实文章)",
    ]
    examples = payload.get("representative_examples") or []
    if examples:
        for item in examples:
            kid = item.get("knowledge_id") if isinstance(item, dict) else None
            title = item.get("title") if isinstance(item, dict) else item
            lines.append(f"- {title}" + (f"  (知识 #{kid})" if kid else ""))
    else:
        lines.append("（无）")
    lines += [
        "",
        "## 覆盖率与证据强弱(引用时要一起说)",
        str(payload.get("coverage_note") or "（未提供）"),
        "",
        f"生成方式: {payload.get('generated_by')}; 模式 id: {payload.get('pattern_id')}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------- 导出

def _file(kind: str, path: str, markdown: str) -> dict[str, Any]:
    return {"kind": kind, "path": path, "markdown": markdown, "chars": len(markdown)}


def task_export(conn: sqlite3.Connection, task_id: int) -> dict[str, Any]:
    """一条任务会导出成哪些 skill 文件。

    **空列表是正常结果, 不是故障**: 没有报告就没有案例文件; 第 7 节没过闸门就没有规律文件。
    页面据此说明"为什么没有", 不渲染一块看起来像抽失败了的空面板。
    """
    task = recipes_module.tasks.get_task(conn, int(task_id))
    if task is None:
        return {"skill": SKILL_NAME, "task_id": int(task_id), "material_id": None, "files": [],
                "note": "任务不存在"}
    material_id = int(task.get("material_id") or 0)
    material = _material(conn, material_id)
    products = recipes_module.products_for_task(conn, int(task_id))
    report = report_module.get_report(conn, int(task_id))

    files: list[dict[str, Any]] = []
    pattern = products.get("pattern")
    if pattern:
        files.append(_file("verified", verified_path(material_id),
                           render_verified(pattern, products.get("recipe"), report, material)))
    if report:
        files.append(_file("case", case_path(task_id, material_id), render_case(report, material)))

    note = ""
    if not pattern and not report:
        note = ("这条任务既没有报告也没有规律 —— failed/blocked 没有可复用的执行路径, "
                "第 7 节没过校验也不出规律。没东西可导出是结论决定的, 不是导出失败。")
    elif not pattern:
        note = ("有报告但没有规律: 第 7 节没过入库闸门(不变量 / 泛化边界 / 三种可执行形态 / "
                "第 6 节校验), 所以只有案例文件。")
    return {
        "skill": SKILL_NAME,
        "task_id": int(task_id),
        "material_id": material_id,
        "title": material.get("title") or "",
        "files": files,
        "note": note,
    }


def export_bundle(conn: sqlite3.Connection) -> dict[str, Any]:
    """全量导出(同步脚本用): catalog 全部 + verified/案例全部。

    返回的是**渲染好的 markdown**, 脚本只管落盘 —— 这样页面预览与磁盘文件必然一致。
    """
    files: list[dict[str, Any]] = []
    conn.row_factory = conn.row_factory or sqlite3.Row
    for row in conn.execute(
        "SELECT payload_json FROM domain_items"
        " WHERE domain = 'vulnerabilities' AND item_type = 'vulnerability_pattern'"
    ):
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except ValueError:
            continue
        payload.pop("model_output", None)
        cwe_ids = payload.get("cwe_ids") or []
        cwe = str(cwe_ids[0]) if cwe_ids else str(payload.get("cluster_key") or "cwe-unknown")
        files.append(_file("catalog", catalog_path(cwe), render_catalog(payload)))

    for row in conn.execute("SELECT report_id FROM writeup_repro_patterns"):
        task_id = int(row["report_id"])
        bundle = task_export(conn, task_id)
        files.extend(bundle["files"])

    return {"skill": SKILL_NAME, "generated_at": now(), "files": files}
