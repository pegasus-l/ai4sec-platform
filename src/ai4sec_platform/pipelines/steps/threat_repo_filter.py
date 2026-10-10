"""采集流水线收尾:给本轮新采到的代码仓补上过滤结论(2026-10-08 领导反馈 #4)。

为什么必须放在流水线里:`/api/threats/targets` 是按 ``threat_repo_filters`` 这张表过滤的,
一次性回填只能覆盖"当时那 8118 个仓"。采集每晚都在进新仓,不补的话新进的空壳/样例仓不会被
过滤 —— 页面上的"已隐藏 N 个"和保留总数会一天天失真,领导看到的过滤会慢慢失效。

为什么是增量而不是整表重算:整表 8118 行约 1.3s,其实也不贵,但本步跑在跑批里,增量(通常每晚
几十个新仓)更省;而且**改规则**这种需要整表刷新的场景本来就该离线跑
``repo_filter --backfill``,不该让每日流水线替人决定"规则变了"。

例外:页面人工添加的单个仓(``payload.raw.manual``)在增量模式下**也每次都重判**(2026-10-10)。
它们多半是组织扫描早就抓回来、上一轮已判过 F1 空壳的仓,不重判的话手动豁免落不了地 ——
用户加了仓,页面上它仍被隐藏。见 ``repo_filter.is_manual_target``。
"""
from __future__ import annotations

from dataclasses import dataclass

from ai4sec_platform.domains.threats import repo_filter
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult


@dataclass
class PersistRepoFilterVerdictsStep:
    name: str = "persist_repo_filter_verdicts"
    step_type: str = "filter"

    def run(self, context: PipelineContext) -> StepResult:
        if not repo_filter.table_ready(context.conn):
            # 表还没回填过(空表)→ 跳过。空表状态下 API 会整体退化成"不过滤",
            # 这一刻补几十行只会让页面显示"隐藏了 3 个"这种更糟的错觉。
            return StepResult(metrics={"skipped": True, "reason": "threat_repo_filters_empty"})
        stats = repo_filter.backfill(context.conn, only_missing=True)
        return StepResult(
            metrics={
                "written": stats["written"],
                "filtered": stats["filtered"],
                "kept": stats["kept"],
                "only_missing": True,
            }
        )
