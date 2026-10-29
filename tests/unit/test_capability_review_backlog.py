"""评审降级不再进库, 改走待重评队列(2026-10-29)。

起因: 2026-10-28 模型网关整段 403, `_fallback_review` 照旧返回 decision=watch / recommended=3,
下游把它当有效评审写库 —— 24 小时灌进 1941 条「待资料补齐」空壳(摘要空、技术点 0、分数卡 60、
score_reason 写着「模型调用降级」), 今日能力页首屏被它们占满, 而它们从来没被真正评过。

这里按"哪一种事故"组织用例, 而不是按函数签名:
  · 降级评审又被写进能力库(这次要堵死的那一条)
  · 降级候选连输入一起丢了(raw 游标每 15 分钟往前走, 事后拿不回来)
  · 一次长宕机把队列里的 attempts 全烧光(队列自己变成第二个回收站)
  · 补评昨天/上个月的候选时把「今日能力」撑爆(created_at 写成今天)
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities import review_backlog
from ai4sec_platform.domains.news import reviewer
from ai4sec_platform.domains.news.tech_map import AgentTechMap
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.steps.capability_raw import (
    RetryDegradedReviewsStep,
    build_store_payload,
    capability_status,
)

TECH_MAP = AgentTechMap({
    "version": "test",
    "dimensions": [
        {"name": "工具调用", "categories": [{"name": "工具集成总线", "points": ["MCP 协议"]}]},
        {"name": "记忆与上下文管理", "categories": [{"name": "长期记忆", "points": ["RAG / 混合检索"]}]},
    ],
})

PATHS = [{"dimension": "工具调用", "category": "工具集成总线", "point": "MCP 协议"}]
HIGH_BREAKDOWN = {
    "map_relevance": 85, "novelty": 80, "technical_depth": 85,
    "engineering_value": 90, "reproducibility": 80, "influence": 95, "freshness": 90,
}

CANDIDATE = {
    "item_key": "asis:raw:1001",
    "title": "一个可部署的 Agent 工具编排框架",
    "summary": "提供工具编排、上下文管理与企业级接入。",
    "code_url": "https://github.com/example/agent-framework",
    "url": "https://example.com/posts/1001",
    "source_type": "github",
    "rule_score": 76,
    "rule_breakdown": {"security": 80},
}


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def _ctx(conn: sqlite3.Connection, tmp_path, **params) -> PipelineContext:
    return PipelineContext(
        run_id="run_test", pipeline_name="capabilities.from_raw_pipeline", domain="capabilities",
        settings=load_settings(), conn=conn, artifact_store=object(), params=params,
    )


@pytest.fixture(autouse=True)
def _stub_tech_map(monkeypatch):
    """不碰磁盘上的 configs/agent_tech_map.yaml: 评审只关心路径能不能被 validate 通过。"""
    monkeypatch.setattr(AgentTechMap, "load", classmethod(lambda cls, project_root: TECH_MAP))


class _StubRouter:
    def active_config(self, profile: str) -> dict:
        return {"provider": "stub"}


def _model_ok(result: dict):
    """返回一次成功的模型调用(签名与 reviewer._call_model_api 一致)。"""
    def _call(router, *, model_profile, prompt, input_payload):
        return result, {"result": result}, False, "stub", 10, [
            {"status": "success", "output": {"result": result}, "latency_ms": 10, "error_message": ""}
        ]
    return _call


def _model_down(error: str = "HTTP Error 403: Forbidden"):
    def _call(router, *, model_profile, prompt, input_payload):
        return {"error": error}, {"error": error}, True, "stub", 5, [
            {"status": "failed", "output": {"attempt": 1}, "latency_ms": 5, "error_message": error}
        ]
    return _call


def _good_review(**overrides) -> dict:
    result = {
        "score_breakdown": dict(HIGH_BREAKDOWN),
        "tech_paths": PATHS,
        "project_nature": "能力框架",
        "theme_descriptor": "可部署的 Agent 工具编排框架",
        "summary_zh": "一个可部署的 Agent 框架, 提供工具编排与上下文管理。",
        "score_reason": "工程完整、有真实代码与评测, 可直接集成。",
        "promo_line": "开箱即用的 Agent 工具编排框架",
        "highlight_line": "工具编排 + 上下文管理一体",
        "security_value": "可用于构建自动化安全分析流水线",
        "reproducibility_assessment": "有 Dockerfile, 可复现",
        "application_advice": "直接接入",
        "recommended_score": 5,
        "capability_type": "工程框架",
        "application_scenarios": ["安全分析流水线"],
        "confidence": 0.9,
    }
    result.update(overrides)
    return result


def _seed_backlog(conn, *, item_key="asis:raw:1001", first_seen_at="2026-10-28T02:00:00Z", item=None, reason="HTTP Error 403: Forbidden") -> None:
    row_item = {**CANDIDATE, **(item or {}), "item_key": item_key}
    review_backlog.enqueue(
        conn, item=row_item,
        input_payload={"candidate": row_item, "tech_map": TECH_MAP.catalog()},
        reason=reason, first_seen_at=first_seen_at,
    )
    conn.commit()


def _capability_rows(conn) -> list[sqlite3.Row]:
    return list(conn.execute("SELECT * FROM domain_items WHERE domain = 'capabilities'"))


# ---------------------------------------------------------------- 建表

def test_init_db_creates_backlog_table_and_is_idempotent() -> None:
    """队列表靠 SCHEMA_SQL 的 CREATE TABLE IF NOT EXISTS 自动迁移, 而 init_db 每个请求都跑。"""
    conn = _conn()
    names = {str(row[0]) for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "capability_review_backlog" in names
    init_db(conn)
    init_db(conn)
    assert review_backlog.count(conn) == 0


def test_item_key_is_unique_so_repeat_degrade_does_not_duplicate() -> None:
    """同一候选每 15 分钟被重扫一次会反复降级 —— 每次都插一行的话队列比库涨得还快。"""
    conn = _conn()
    _seed_backlog(conn)
    _seed_backlog(conn, reason="another failure")
    assert review_backlog.count(conn) == 1
    row = conn.execute("SELECT reason FROM capability_review_backlog").fetchone()
    assert row["reason"] == "another failure"


def test_enqueue_rejects_missing_item_key() -> None:
    """没有 item_key 就没法去重/重评: 抛给调用方记日志, 不许静默吞。"""
    conn = _conn()
    with pytest.raises(ValueError):
        review_backlog.enqueue(conn, item={"title": "无 key"}, input_payload={}, reason="x")


def test_enqueue_keeps_attempts_and_first_seen_at_on_repeat() -> None:
    """重复降级只刷新输入与原因: attempts 与 first_seen_at 是"这条候选等了多久"的证据。"""
    conn = _conn()
    _seed_backlog(conn, first_seen_at="2026-10-20T00:00:00Z")
    row_id = int(conn.execute("SELECT id FROM capability_review_backlog").fetchone()[0])
    review_backlog.record_failure(conn, row_id, "bad schema")
    _seed_backlog(conn, first_seen_at="2026-10-29T00:00:00Z")
    row = conn.execute("SELECT attempts, first_seen_at FROM capability_review_backlog").fetchone()
    assert row["attempts"] == 1
    assert row["first_seen_at"] == "2026-10-20T00:00:00Z"


def test_prune_item_drops_bulky_fields() -> None:
    """readme/raw 已经在 input_json 里, item_json 再存一份就是双倍体积(候选上千条时按 MB 算)。"""
    kept = review_backlog.prune_item({**CANDIDATE, "readme": "x" * 10000, "raw": {"body": "..."}})
    assert "readme" not in kept and "raw" not in kept
    assert kept["item_key"] == CANDIDATE["item_key"]
    assert kept["code_url"] == CANDIDATE["code_url"]


def test_pending_orders_by_attempts_then_arrival() -> None:
    """先重试失败次数少的, 再先来先补 —— 否则一直失败的条目会永远挡在最前面。"""
    conn = _conn()
    _seed_backlog(conn, item_key="asis:a")
    _seed_backlog(conn, item_key="asis:b")
    _seed_backlog(conn, item_key="asis:c")
    row_b = int(conn.execute("SELECT id FROM capability_review_backlog WHERE item_key='asis:b'").fetchone()[0])
    review_backlog.record_failure(conn, row_b, "bad schema")
    assert [r["item_key"] for r in review_backlog.pending(conn, 10)] == ["asis:a", "asis:c", "asis:b"]


def test_record_failure_drops_at_max_attempts() -> None:
    conn = _conn()
    _seed_backlog(conn)
    row_id = int(conn.execute("SELECT id FROM capability_review_backlog").fetchone()[0])
    for _ in range(review_backlog.MAX_ATTEMPTS - 1):
        assert review_backlog.record_failure(conn, row_id, "bad schema") is False
    assert review_backlog.record_failure(conn, row_id, "bad schema") is True
    assert review_backlog.count(conn) == 0


# ---------------------------------------------------------------- 降级评审不再进库

def test_fallback_review_carries_degraded_reason() -> None:
    """`degraded_reason` 是「这不是一次真评审」的唯一真源, 调用方全靠它分流。"""
    review = reviewer._fallback_review(CANDIDATE, TECH_MAP, "HTTP Error 403: Forbidden")
    assert review["degraded_reason"] == "HTTP Error 403: Forbidden"
    assert review["score_reason"].startswith("模型调用降级")


def test_degraded_review_is_not_stored_and_is_enqueued(monkeypatch) -> None:
    """这次要堵死的那一条: 网关 403 时既不能写出库条目, 也不能把候选丢掉。"""
    conn = _conn()
    monkeypatch.setattr(reviewer, "LLMRouter", _StubRouter)
    monkeypatch.setattr(reviewer, "_call_model_api", _model_down())

    selected, metrics = reviewer.review_candidates(
        conn, [dict(CANDIDATE)], run_id="run_test", project_root=_ctx(conn, None).settings.project_root,
        model_profile="stub", min_decision="all",
    )

    assert selected == [], "降级评审不得进返回值 —— 下游 StoreCapabilitiesStep 会把它当结论写库"
    assert metrics["degraded"] == 1
    assert metrics["backlog_enqueued"] == 1
    assert _capability_rows(conn) == []
    pending = review_backlog.pending(conn, 10)
    assert len(pending) == 1
    assert pending[0]["item_key"] == CANDIDATE["item_key"]
    assert "403" in pending[0]["reason"]
    # 输入必须原样留着: raw 游标每 15 分钟往前走, 事后重算拿不回来
    assert pending[0]["input_payload"]["candidate"]["title"] == CANDIDATE["title"]


def test_real_review_still_flows_through(monkeypatch) -> None:
    """反向护栏: 正常评审不受影响。"""
    conn = _conn()
    monkeypatch.setattr(reviewer, "LLMRouter", _StubRouter)
    monkeypatch.setattr(reviewer, "_call_model_api", _model_ok(_good_review()))

    selected, metrics = reviewer.review_candidates(
        conn, [dict(CANDIDATE)], run_id="run_test", project_root=_ctx(conn, None).settings.project_root,
        model_profile="stub", min_decision="all",
    )

    assert len(selected) == 1
    assert metrics["degraded"] == 0
    assert review_backlog.count(conn) == 0


# ---------------------------------------------------------------- 重评

def test_retry_stores_and_restores_created_at(monkeypatch) -> None:
    """补评只该把条目加回库里, 不该让它们冒充「今天新发现的」。"""
    conn = _conn()
    _seed_backlog(conn, first_seen_at="2026-10-20T03:00:00Z")
    monkeypatch.setattr(reviewer, "LLMRouter", _StubRouter)
    monkeypatch.setattr(reviewer, "_call_model_api", _model_ok(_good_review()))

    result = RetryDegradedReviewsStep().run(_ctx(conn, None))

    rows = _capability_rows(conn)
    assert result.metrics["stored"] == 1
    assert len(rows) == 1
    assert rows[0]["created_at"] == "2026-10-20T03:00:00Z"
    payload = json.loads(rows[0]["payload_json"])
    assert payload["display_summary"] == _good_review()["summary_zh"]
    assert payload["tech_points"] == ["MCP 协议"]
    assert payload["repro_status"] == "candidate"
    assert review_backlog.count(conn) == 0


def test_retry_provider_down_keeps_queue_and_burns_no_attempts(monkeypatch) -> None:
    """整批都失败 = 探活失败: 一次长宕机不能把队列耗成永久放弃。"""
    conn = _conn()
    _seed_backlog(conn)
    monkeypatch.setattr(reviewer, "LLMRouter", _StubRouter)
    monkeypatch.setattr(reviewer, "_call_model_api", _model_down())

    result = RetryDegradedReviewsStep().run(_ctx(conn, None))

    assert result.metrics["provider_down"] == 1
    assert _capability_rows(conn) == []
    row = conn.execute("SELECT attempts FROM capability_review_backlog").fetchone()
    assert row is not None and row["attempts"] == 0


def test_retry_aborts_on_first_chunk_when_gateway_is_down(monkeypatch) -> None:
    """网关宕机时不能把整批都提交出去: 每调用要耗满 3 次重试的退避, 会把一个 15 分钟节拍拖成半小时。"""
    conn = _conn()
    for i in range(25):
        _seed_backlog(conn, item_key=f"asis:raw:{i}")
    calls = []

    def _down(router, *, model_profile, prompt, input_payload):
        calls.append(1)
        return _model_down()(router, model_profile=model_profile, prompt=prompt, input_payload=input_payload)

    monkeypatch.setattr(reviewer, "LLMRouter", _StubRouter)
    monkeypatch.setattr(reviewer, "_call_model_api", _down)

    result = RetryDegradedReviewsStep().run(_ctx(conn, None, retry_chunk=20))

    assert result.metrics["provider_down"] == 1
    assert len(calls) == 20, "首块全灭就该熔断, 不该继续调后面的 5 条"
    assert review_backlog.count(conn) == 25
    assert {r["attempts"] for r in review_backlog.pending(conn, 30)} == {0}


def test_retry_rejected_leaves_the_library_alone(monkeypatch) -> None:
    """重评结论是 rejected: 出队, 但绝不写库(降级时的 watch 本来就没有入库资格)。"""
    conn = _conn()
    _seed_backlog(conn)
    monkeypatch.setattr(reviewer, "LLMRouter", _StubRouter)
    monkeypatch.setattr(reviewer, "_call_model_api", _model_ok(_good_review(tech_paths=[])))

    result = RetryDegradedReviewsStep().run(_ctx(conn, None))

    assert result.metrics["rejected"] == 1
    assert _capability_rows(conn) == []
    assert review_backlog.count(conn) == 0


def test_retry_schema_mismatch_counts_as_one_failure(monkeypatch) -> None:
    """模型回了话但不是评审 schema: 算这条候选的一次失败, 不重复入队。"""
    conn = _conn()
    _seed_backlog(conn)
    row_id = int(conn.execute("SELECT id FROM capability_review_backlog").fetchone()[0])
    monkeypatch.setattr(reviewer, "LLMRouter", _StubRouter)
    monkeypatch.setattr(reviewer, "_call_model_api", _model_ok({"hello": "world"}))

    RetryDegradedReviewsStep().run(_ctx(conn, None))

    row = conn.execute("SELECT id, attempts FROM capability_review_backlog").fetchone()
    assert row["id"] == row_id
    assert row["attempts"] == 1
    assert _capability_rows(conn) == []


def test_retry_skips_repo_already_in_library(monkeypatch) -> None:
    """主链路已经用一次真评审写过这个仓库 → 以库里那份为准, 只出队, 不再插第二条。"""
    conn = _conn()
    conn.execute(
        "INSERT INTO domain_items (domain, item_type, title, status, payload_json, created_at, updated_at) "
        "VALUES ('capabilities', 'capability', '库里已有的那条', '待复现验证', ?, '2026-10-27T00:00:00Z', '2026-10-27T00:00:00Z')",
        (json.dumps({"code_url": CANDIDATE["code_url"]}),),
    )
    conn.commit()
    _seed_backlog(conn)
    monkeypatch.setattr(reviewer, "LLMRouter", _StubRouter)
    monkeypatch.setattr(reviewer, "_call_model_api", _model_ok(_good_review()))

    RetryDegradedReviewsStep().run(_ctx(conn, None))

    assert len(_capability_rows(conn)) == 1
    assert review_backlog.count(conn) == 0


def test_retry_empty_queue_is_a_noop(monkeypatch) -> None:
    conn = _conn()
    monkeypatch.setattr(reviewer, "_call_model_api", lambda *a, **k: pytest.fail("空队列不该发起模型调用"))
    result = RetryDegradedReviewsStep().run(_ctx(conn, None))
    assert result.metrics["pending"] == 0


# ---------------------------------------------------------------- 与 StoreCapabilitiesStep 同口径

def test_capability_status_matches_store_contract() -> None:
    assert capability_status("selected", 5) == "待复现验证"
    assert capability_status("watch", 4) == "待复现验证"
    assert capability_status("watch", 3) == "待资料补齐"
    assert capability_status("rejected", 5) == "已淘汰"


def test_vertical_app_never_enters_the_library() -> None:
    """垂直应用一律已淘汰(2026-10-29 用户判定: 与 AI for Sec 业务方向无关)。

    只压在性质封顶(≤65 / rec≤3)是不够的 —— 那样它会落「待资料补齐」, 仍然出现在今日能力里
    (实测争议条目 isemsez/med_assistant)。规则也必须是幂等的: 每 15 分钟的资讯重扫会用
    review 结论重算 status, 只改数据下一轮就漂回去。
    """
    for decision in ("selected", "watch", "rejected"):
        for recommended in (1, 3, 5):
            assert capability_status(decision, recommended, "垂直应用") == "已淘汰"
    # 其余三类与历史口径不变: 能力框架的 watch/3 照样是待资料补齐
    assert capability_status("watch", 3, "能力框架") == "待资料补齐"
    assert capability_status("watch", 4, "教学演示") == "待复现验证"
    assert capability_status("watch", 4, "") == "待复现验证"


def test_vertical_app_payload_has_no_repro_status() -> None:
    """已淘汰的条目不是复现候选 —— 入库模板无条件带的 candidate 戳要摘掉(同非 web 那条教训)。"""
    vertical = {**_good_review(), "project_nature": "垂直应用"}
    review = reviewer._normalize_review(vertical, CANDIDATE, TECH_MAP)
    payload = build_store_payload(CANDIDATE, review)
    assert "repro_status" not in payload
    # 横向能力照旧带 candidate, 由后续 web 分类改成终态
    normal = reviewer._normalize_review(_good_review(), CANDIDATE, TECH_MAP)
    assert build_store_payload(CANDIDATE, normal)["repro_status"] == "candidate"


def test_build_store_payload_keeps_v1_contract() -> None:
    """重评落库与主链路落库必须用同一份 payload, 否则重评回来的条目在页面上长得不一样。"""
    review = reviewer._normalize_review(_good_review(), CANDIDATE, TECH_MAP)
    payload = build_store_payload(CANDIDATE, review)
    for key in ("review", "display_title", "display_summary", "assessment", "implementation_depth",
                "repro_status", "conversion_status", "source_news_item", "tech_points"):
        assert key in payload
    assert payload["repro_status"] == "candidate"
    assert payload["assessment"]["recommended_score"] == review["recommended_score"]


def test_retry_stops_at_budget_and_leaves_the_rest_queued(monkeypatch) -> None:
    """排水要连着跑几十轮: 单轮跑过 15 分钟节拍, 下一轮会被自己的全局锁 skip 掉。

    2026-10-29 实测: 单次重评约 110s, 100 条 = 12.9 分钟, 整批 15.5 分钟 —— 刚好越过节拍。
    到点收工时已经处理过的照常落库, 没轮到的原样留在队列里(不烧 attempts, 不算失败)。
    """
    conn = _conn()
    for i in range(30):
        _seed_backlog(conn, item_key=f"asis:raw:{i}",
                      item={"code_url": f"https://github.com/example/repo-{i}"})
    monkeypatch.setattr(reviewer, "LLMRouter", _StubRouter)
    monkeypatch.setattr(reviewer, "_call_model_api", _model_ok(_good_review()))

    result = RetryDegradedReviewsStep().run(
        _ctx(conn, None, retry_budget_seconds=0, retry_chunk=10)
    )

    assert result.metrics["budget_exhausted"] == 1
    assert result.metrics["reviewed"] == 10, "预算到点: 只跑完第一块(正好一波并发)"
    assert result.metrics["stored"] == 10
    assert review_backlog.count(conn) == 20, "没轮到的留在队列里等下一轮"
