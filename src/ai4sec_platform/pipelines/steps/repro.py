"""能力复现 pipeline steps。

复现由独立持久 Worker 异步执行，pipeline 只负责：
  1. 选择候选
  2. 创建 queued task
  3. 从已完成的 task 提取报告 + 回写能力卡

实际等待和实时日志推送在 API 层（SSE 端点）处理。
"""
from __future__ import annotations

from dataclasses import dataclass
import socket
from typing import Any

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.domains.capabilities.adapters.repro_results import update_capability_from_report
from ai4sec_platform.domains.capabilities.repro_jobs import request_repro_cleanup
from ai4sec_platform.domains.capabilities.repro_policy import ReproQuotaExceededError, enqueue_repro_task
from ai4sec_platform.domains.capabilities.selectors import pick_top_repro_candidates
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class SelectReproCandidatesStep:
    """选择 top N 复现候选（迁自旧 v1 db.py pick_top_repro_candidates）"""
    name: str = "select_repro_candidates"
    step_type: str = "select"

    def run(self, context: PipelineContext) -> StepResult:
        n = int(context.params.get("repro_topn", 3))
        web_only = bool(context.params.get("web_only", False))
        candidates = pick_top_repro_candidates(context.conn, n=n, web_only=web_only)
        context.outputs["repro_candidates"] = candidates
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="repro_candidates",
            name="capabilities/repro_candidates.json",
            data={"candidates": [{"item_id": c["id"], "title": c.get("title", ""), "repo_url": c.get("_repo_url", "")} for c in candidates]},
        )
        return StepResult(
            metrics={"candidates": len(candidates), "web_only": web_only},
            artifacts=[artifact],
        )


@dataclass
class StartReproTasksStep:
    """为每个候选创建持久任务，由 Repro Worker 异步认领。"""
    name: str = "start_repro_tasks"
    step_type: str = "start_repro"

    def run(self, context: PipelineContext) -> StepResult:
        candidates: list[dict[str, Any]] = context.outputs.get("repro_candidates") or []
        started: list[int] = []
        rejected: list[dict[str, Any]] = []

        for candidate in candidates:
            item_id = candidate["id"]
            repo_url = candidate.get("_repo_url", "")

            try:
                task_id = enqueue_repro_task(
                    context.conn,
                    item_id=item_id,
                    repo_url=repo_url,
                    trigger=context.params.get("trigger", "auto"),
                )
            except ReproQuotaExceededError as exc:
                rejected.append({"item_id": item_id, "code": exc.code, "message": str(exc)})
                continue

            # 旧失败任务由 Worker 清理，Pipeline 不直接操作 Docker。
            for old_task in repo.list_repro_tasks(context.conn, item_id=item_id, include_cleaned=True):
                if old_task["status"] in ("failed", "timeout", "stopped"):
                    request_repro_cleanup(context.conn, int(old_task["id"]))

            # 决定是否 Web 复现
            payload = candidate.get("payload") or {}
            web_port = None
            if payload.get("is_web") or payload.get("demo_url"):
                web_port = _alloc_web_port(context.conn)
                if web_port:
                    repo.update_repro_task(context.conn, task_id=task_id, web_port=web_port)

            started.append(task_id)

        context.outputs["repro_task_ids"] = started
        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="repro_tasks",
            name="capabilities/repro_tasks.json",
            data={"task_ids": started, "count": len(started), "rejected": rejected},
        )
        return StepResult(
            metrics={"started": len(started), "rejected": len(rejected), "task_ids": started},
            artifacts=[artifact],
        )


@dataclass
class ExtractReproReportsStep:
    """从已完成的 task 提取报告 + 回写能力卡（处理 pipeline 启动时已完成的 task）"""
    name: str = "extract_repro_reports"
    step_type: str = "extract_report"

    def run(self, context: PipelineContext) -> StepResult:
        task_ids: list[int] = context.outputs.get("repro_task_ids") or []
        extracted = 0
        updated = 0

        for task_id in task_ids:
            task = repo.get_repro_task(context.conn, task_id)
            if not task:
                continue
            if task["status"] not in ("success", "partial", "failed", "timeout"):
                continue  # 还在跑，跳过

            report_json = task.get("report_json") or "{}"
            if report_json and report_json != "{}":
                result = update_capability_from_report(
                    context.conn,
                    item_id=task["item_id"],
                    report=report_json,
                )
                if result.get("updated"):
                    updated += 1
                extracted += 1

        artifact = context.artifact_store.write_json(
            context.conn,
            run_id=context.run_id,
            artifact_type="repro_reports",
            name="capabilities/repro_reports.json",
            data={"extracted": extracted, "updated": updated},
        )
        return StepResult(
            metrics={"extracted": extracted, "updated": updated},
            artifacts=[artifact],
        )


def _alloc_web_port(conn) -> int | None:
    """分配 Web 端口（从 18000 开始，跳过已用端口）"""
    import os
    base = int(os.environ.get("REPRO_WEB_PORT_BASE", "18000"))
    max_port = int(os.environ.get("REPRO_WEB_PORT_MAX", "18999"))

    # 查已用端口
    rows = conn.execute(
        "SELECT DISTINCT web_port FROM capability_repro_tasks WHERE web_port IS NOT NULL AND status IN ('queued', 'running')"
    ).fetchall()
    used = {row["web_port"] for row in rows}

    for port in range(base, max_port + 1):
        if port not in used and _port_is_available(port):
            return port
    return None


def _port_is_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True
