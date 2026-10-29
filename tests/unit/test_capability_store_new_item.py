"""StoreCapabilitiesStep「新增条目」分支的回归测试(2026-10-29)。

背景: 线上 10-29 两个 `capabilities.from_news_pipeline` 跑批在 store_capabilities 步失败,
报 `name 'display_summary' is not defined`。根因是 2026-08-10 评分引擎重构时把这一行写成了
`summary=display_summary`, 而 `display_summary` 只是 `build_store_payload()` 里的局部变量。

为什么藏了两个半月才暴露: 这个 NameError 只在**真出现新能力**时触发(走 create 分支);
同一批仓库重复被发现时走的是 update 分支, 根本不看这一行。所以每次"发现了一个新项目"
那一晚的跑批都是整步失败, 前一步已经算完的评审结论一起丢掉。

这里锁住三件事: 新增分支不再抛 NameError; 落库的 summary 用的是评审给的 summary_zh;
同一条目第二次进来(命中 code_url 去重)走更新分支。
"""
from __future__ import annotations

import sqlite3

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.pipelines.base import PipelineContext
from ai4sec_platform.pipelines.steps.capability_raw import StoreCapabilitiesStep


CANDIDATE = {
    "item_key": "asis:raw:2001",
    "title": "一个可部署的 Agent 工具编排框架",
    "summary": "提供工具编排、上下文管理与企业级接入。",
    "code_url": "https://github.com/example/agent-framework-x",
    "url": "https://example.com/posts/2001",
    "source_type": "github",
    "rule_score": 76,
    "rule_breakdown": {"security": 80},
}

REVIEW = {
    "decision": "accepted",
    "score": 8,
    "recommended_score": 82,
    "theme": "Agent 工具编排框架",
    "theme_descriptor": "把工具调用、上下文与多 Agent 编排收进一个可部署的服务",
    "work_name": "agent-framework-x",
    "summary_zh": "一套可部署的 Agent 工具编排框架, 统一工具注册、上下文与多 Agent 协作。",
    "topic": "Agent 框架",
    "capability_type": "framework",
    "project_nature": "安全工具",
    "promo_line": "把多 Agent 编排做成一个服务",
    "highlight_line": "统一工具注册与上下文",
}


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def _ctx(conn: sqlite3.Connection) -> PipelineContext:
    return PipelineContext(
        run_id="run_test", pipeline_name="capabilities.from_news_pipeline", domain="capabilities",
        settings=load_settings(), conn=conn, artifact_store=object(), params={},
    )


def _run(conn: sqlite3.Connection) -> dict:
    ctx = _ctx(conn)
    ctx.outputs["reviewed_items"] = [dict(CANDIDATE, review=dict(REVIEW))]
    result = StoreCapabilitiesStep().run(ctx)
    conn.commit()
    return result.metrics


def test_new_capability_is_stored_with_review_summary() -> None:
    conn = _conn()
    metrics = _run(conn)
    assert metrics["created"] == 1, metrics

    row = repo.get_domain_item_by_repo(conn, domain="capabilities", repo_url=CANDIDATE["code_url"])
    assert row is not None
    # 落库的 summary 用评审给的摘要, 不是候选自带的原文简介
    assert row["summary"] == REVIEW["summary_zh"]
    payload = dict(row["payload"] or {})
    assert payload["display_summary"] == REVIEW["summary_zh"]
    assert payload["display_title"] == REVIEW["theme"]


def test_same_repo_second_time_goes_to_update_branch() -> None:
    conn = _conn()
    assert _run(conn)["created"] == 1
    metrics = _run(conn)
    assert metrics["created"] == 0 and metrics["updated"] == 1, metrics
    rows = conn.execute(
        "SELECT COUNT(*) FROM domain_items WHERE domain='capabilities' AND item_type='capability'"
    ).fetchone()[0]
    assert rows == 1
