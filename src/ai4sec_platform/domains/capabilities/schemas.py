from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class CapabilityCandidate(BaseModel):
    """能力候选 - 从资讯高分条目派生，待评估"""

    title: str
    source_url: str = ""
    code_url: str = ""
    source_news_score: float | None = None
    status: str = "待能力评估"


class CapabilityCard(BaseModel):
    """能力卡 - 评估完生成，对齐 demo today.json / library.json 字段"""

    title: str
    theme: str = ""
    source_type: str = "arxiv"
    source: str = ""
    source_url: str = ""
    code_url: str = ""
    capability_type: str = ""  # 验证与评估|推理与规划|工具调用|...
    sub_type: str = ""  # 幻觉缓解|代码审计|...
    application_scenarios: list[str] = Field(default_factory=list)
    score: int = 3  # 1-5
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    summary: str = ""
    highlight: str = ""
    review: str = ""
    tech_points: list[str] = Field(default_factory=list)
    implementation_depth: dict[str, Any] = Field(default_factory=dict)
    repro_status: str = "no_code"  # no_code|candidate|in_progress|success|partial|failed
    conversion_status: str = "未启动"  # 持续观察|已转化|已放弃|未启动
    status: str = "active"
    evidence: list[Any] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ConversionRecord(BaseModel):
    """能力转化记录 - 对齐 demo conversions.json"""

    title: str
    capability_id: int | None = None
    status: str = "持续观察"  # 持续观察|已转化|已放弃
    scenario: str = ""
    owner: str = ""
    next_action: str = ""
    notes: str = ""


class ReproReport(BaseModel):
    """复现报告 11+ 字段 - 存 capability_repro_tasks.report_json

    普通项目（REPRO_PROMPT）字段：level/status/summary/project_type/environment/steps/run_result/blockers/gotchas/usage
    Web 项目（WEB_REPRO_PROMPT）追加：is_web/web_started/web_framework/start_command/verify
    """

    level: str = "L1"  # L1|L2|L3
    status: str = "failed"  # success|partial|failed
    summary: str = ""
    project_type: str = ""  # python|node|rust|go|其他
    environment: dict[str, Any] = Field(default_factory=dict)
    steps: list[dict[str, Any]] = Field(default_factory=list)
    run_result: dict[str, Any] = Field(default_factory=dict)
    blockers: list[str] = Field(default_factory=list)
    gotchas: list[str] = Field(default_factory=list)
    usage: dict[str, Any] = Field(default_factory=dict)
    # Web 项目追加字段
    is_web: bool = False
    web_started: bool = False
    web_framework: str = ""
    start_command: str = ""
    verify: str = ""
    core_workflow: dict[str, Any] = Field(default_factory=dict)
    acceptance_issues: list[str] = Field(default_factory=list)


class ReproTaskResponse(BaseModel):
    """复现任务 API 响应模型 - 对应 capability_repro_tasks 表"""

    id: int
    item_id: int
    repo_url: str
    status: str  # queued|running|success|partial|failed|stopped|timeout|cleaned
    container_name: str = ""
    workspace_path: str = ""
    created_at: str = ""
    finished_at: str = ""
    cleaned_at: str = ""
    trigger: str = "manual"
    repro_strategy: str = "cli"
    report: ReproReport | None = None
    web_port: int | None = None
    web_url: str = ""
    result: str = ""
    log_excerpt: str = ""  # API 层截断最后 N 行，避免大日志爆响应

    @classmethod
    def from_row(cls, row: dict[str, Any], *, log_tail_lines: int = 200) -> "ReproTaskResponse":
        """从 DB row 构造响应，自动解析 report_json + 截断 log"""
        report: ReproReport | None = None
        report_json = row.get("report_json") or row.get("report") or "{}"
        if isinstance(report_json, str):
            try:
                import json
                report_data = json.loads(report_json)
                if report_data:
                    report = ReproReport(**{k: v for k, v in report_data.items() if k in ReproReport.model_fields})
            except Exception:
                report = None
        elif isinstance(report_json, dict) and report_json:
            report = ReproReport(**{k: v for k, v in report_json.items() if k in ReproReport.model_fields})

        log = row.get("log") or ""
        log_lines = log.splitlines()
        log_excerpt = "\n".join(log_lines[-log_tail_lines:]) if len(log_lines) > log_tail_lines else log

        return cls(
            id=row["id"],
            item_id=row["item_id"],
            repo_url=row["repo_url"],
            status=row["status"],
            container_name=row.get("container_name", ""),
            workspace_path=row.get("workspace_path", ""),
            created_at=row.get("created_at", ""),
            finished_at=row.get("finished_at", ""),
            cleaned_at=row.get("cleaned_at", ""),
            trigger=row.get("trigger", "manual"),
            repro_strategy=row.get("repro_strategy", "cli"),
            report=report,
            web_port=row.get("web_port"),
            web_url=row.get("web_url", ""),
            result=row.get("result", ""),
            log_excerpt=log_excerpt,
        )
