"""复现报告提取 + 能力卡回写。

迁自旧 v1 repro.py 的 extract_report/_parse_report_json/_try_loose_json（在 repro_runner.py 中），
本模块提供从报告回写能力卡的适配层。
"""
from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.capabilities.adapters.repro_runner import enforce_report_acceptance, extract_report


def normalize_repro_result(item: dict) -> dict:
    """保留现有接口兼容"""
    return {"repro_status": item.get("status", "unknown"), **item}


def update_capability_from_report(
    conn,
    *,
    item_id: int,
    report: dict[str, Any] | str | None,
) -> dict[str, Any]:
    """从复现报告回写能力卡（domain_items payload + status + score）。

    报告 11+ 字段（决策 7 完整保留）:
      level/status/summary/project_type/environment/steps/run_result/blockers/gotchas/usage
      Web 项目追加: is_web/web_started/web_framework/start_command/verify

    回写逻辑:
      1. report.status → domain_item.status（success → "已复现", partial → "部分复现", failed → "复现失败"）
      2. report 整体 → payload.repro_report（保留全部 11+ 字段）
      3. report.summary → payload.repro_summary
      4. report.usage → payload.usage（用户使用说明）
      5. report.is_web → payload.is_web（修正 Web 分类）
    """
    from ai4sec_platform.db import repositories as repo

    if not report:
        return {"updated": False, "reason": "no report"}

    # 如果 report 是字符串，先解析
    if isinstance(report, str):
        report = extract_report(report)
        if not report:
            return {"updated": False, "reason": "report string parse failed"}

    report = enforce_report_acceptance(report)
    if not report:
        return {"updated": False, "reason": "report acceptance failed"}

    # 映射报告 status → domain_item status
    rep_status = report.get("status", "failed")
    status_map = {
        "success": "已复现",
        "partial": "部分复现",
        "failed": "复现失败",
    }
    new_status = status_map.get(rep_status, "复现失败")

    # 构造回写 payload
    payload_update: dict[str, Any] = {
        "repro_report": report,  # 完整报告（11+ 字段）
        "repro_summary": report.get("summary", ""),
        "repro_status": rep_status,
        "usage": report.get("usage", {}),
        "blockers": report.get("blockers", []),
        "gotchas": report.get("gotchas", []),
    }

    # Web 项目追加字段
    if "is_web" in report:
        payload_update["is_web"] = bool(report.get("is_web"))
        payload_update["web_started"] = bool(report.get("web_started", False))
        if report.get("web_framework"):
            payload_update["web_framework"] = report["web_framework"]

    # 环境信息
    env = report.get("environment", {})
    if env:
        payload_update["repro_environment"] = env

    repo.update_domain_item(
        conn,
        item_id=item_id,
        status=new_status,
        payload=payload_update,
        metrics={
            "repro_level": report.get("level", ""),
            "repro_project_type": report.get("project_type", ""),
            "repro_needs_gpu": env.get("needs_gpu", False) if env else False,
            "repro_needs_api_key": env.get("needs_api_key", False) if env else False,
        },
    )

    return {
        "updated": True,
        "new_status": new_status,
        "report_status": rep_status,
        "report_level": report.get("level", ""),
    }


def extract_and_update(
    conn,
    *,
    item_id: int,
    full_log: str,
) -> dict[str, Any]:
    """从完整日志提取报告并回写能力卡（供 CaptureReproLogsStep 调用）"""
    report = extract_report(full_log)
    return update_capability_from_report(conn, item_id=item_id, report=report)
