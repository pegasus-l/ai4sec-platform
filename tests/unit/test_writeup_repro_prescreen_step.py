"""T1.3 预筛流水线步骤(2026-11-11)。

这一层要守住三件事, 每一件错了都**不会报错**:

- 模型报错被写成结论 → 库里出现"这篇没有 PoC"的谎, 而且看起来和真的没区别;
- 每轮重筛同样的素材 → 白花 token, 结论还会抖动;
- 整批只在最后 commit → 中途被杀全丢(T1.2 实测丢过 16 条)。

另外一条是性能上的硬要求: 规则层拒掉的素材**一次模型都不能调**(线上比例约 3:4)。
"""
from __future__ import annotations

import json
import sqlite3

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities.writeup_repro import screener, screener_rules, store
from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.steps.writeup_repro import MODEL_PROFILE, ScreenWriteupMaterialsStep

TEXT = """# foo 堆溢出

foo 2.3.1 的 parse() 有堆溢出, 作者给了完整 PoC。

```bash
git clone https://github.com/acme/foo
cd foo && git checkout 2.3.1
make
```

```c
int main(void) {
  char *p = malloc(8);
  memcpy(p, buf, 4096);
  return 0;
}
```

影响 foo <= 2.3.1。
"""

#: 规则层就会拒掉的素材: 没有代码块。
NO_CODE = "这是一篇没有代码的新闻稿, 讲某个厂商又发了一个公告。"

POC_C = "int main(void) {\n  char *p = malloc(8);\n  memcpy(p, buf, 4096);\n  return 0;\n}"

RESULT_OK = {
    "is_writeup": True,
    "has_poc": True,
    "poc_lang": "c",
    "poc_code": POC_C,
    "target_kind": "oss_repo",
    "target_repo": "https://github.com/acme/foo",
    "target_version": "2.3.1",
    "env_hint": "linux x86_64",
    "claimed_effect": "parse() 堆溢出, 可崩溃",
    "evidence_quote": "foo 2.3.1 的 parse() 有堆溢出, 作者给了完整 PoC。",
    "confidence": 0.92,
}


# ---------------------------------------------------------------- 脚手架

class _Provider:
    def __init__(self, result=None, error: Exception | None = None) -> None:
        self.result = dict(result or RESULT_OK)
        self.error = error
        self.calls = 0

    def complete_json(self, *, prompt, payload):
        self.calls += 1
        if self.error:
            raise self.error
        return {"provider": "fake", "model": "fake-1", "result": self.result}


class _Router:
    def __init__(self, provider: _Provider) -> None:
        self.provider = provider

    def provider_for(self, profile):
        assert profile == screener.MODEL_PROFILE
        return self.provider


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def _material(conn: sqlite3.Connection, item_id: int, text: str) -> None:
    conn.execute(
        "INSERT INTO domain_items (id, domain, item_type, title, status, source, source_url, primary_date, payload_json, created_at, updated_at) "
        "VALUES (?, 'vulnerabilities', 'material', ?, 'active', 'src', 'http://x', '2026-11-01', ?, 'now', 'now')",
        (item_id, f"t{item_id}", json.dumps({"cleaned_text": text})),
    )
    conn.commit()


def _ctx(conn: sqlite3.Connection, **params) -> PipelineContext:
    return PipelineContext(
        run_id="run_t13",
        pipeline_name="capabilities.writeup_repro_prescreen",
        domain="capabilities",
        settings=load_settings(),
        conn=conn,
        artifact_store=object(),
        params=params,
    )


def _patch_model(monkeypatch, provider: _Provider) -> None:
    monkeypatch.setattr(screener, "LLMRouter", lambda: _Router(provider))


# ---------------------------------------------------------------- 规则层先行

def test_rule_rejected_material_is_written_without_calling_model(monkeypatch) -> None:
    """规则层拒掉的也要落一行 —— 否则漏斗的分母和拒绝桶都对不上。"""
    conn = _conn()
    _material(conn, 1, NO_CODE)
    provider = _Provider()
    _patch_model(monkeypatch, provider)

    metrics = ScreenWriteupMaterialsStep().run(_ctx(conn)).metrics

    row = store.get_candidate(conn, 1)
    assert row["screened_by"] == "rules"
    assert row["screenable"] == 0
    assert row["reject_reason"] == "not_writeup"
    assert row["rule_version"] == screener_rules.SCREENER_VERSION
    assert provider.calls == 0, "规则层拒掉的素材不该消耗一次模型调用"
    assert metrics["rule_rejected"] == 1
    assert metrics["model_called"] == 0


def test_screenable_material_goes_through_the_model(monkeypatch) -> None:
    conn = _conn()
    _material(conn, 2, TEXT)
    provider = _Provider()
    _patch_model(monkeypatch, provider)

    metrics = ScreenWriteupMaterialsStep().run(_ctx(conn)).metrics

    row = store.get_candidate(conn, 2)
    assert row["screened_by"] == "llm"
    assert row["screenable"] == 1
    assert row["target_repo"] == "github:acme/foo"
    assert row["target_version"] == "2.3.1"
    assert provider.calls == 1
    assert metrics["screenable"] == 1


# ---------------------------------------------------------------- 报错不是结论

def test_model_error_is_not_persisted_and_comes_back_next_run(monkeypatch) -> None:
    conn = _conn()
    _material(conn, 3, TEXT)
    provider = _Provider(error=RuntimeError("gateway 502"))
    _patch_model(monkeypatch, provider)
    step = ScreenWriteupMaterialsStep()

    first = step.run(_ctx(conn)).metrics

    assert store.get_candidate(conn, 3) is None, "模型报错不许落成任何结论"
    assert first["errors"] == 1
    assert first["written"] == 0
    assert first["provider_down"] == 1

    provider.error = None
    second = step.run(_ctx(conn)).metrics

    assert second["pending"] == 1, "上一轮报错的素材必须被重新挑出来"
    assert store.get_candidate(conn, 3)["screenable"] == 1


def test_provider_down_stops_after_the_first_chunk(monkeypatch) -> None:
    """首波全灭就当网关不可用: 后面的行原样留在队列里, 不为它们各耗一次退避。"""
    conn = _conn()
    for item_id in (1, 2, 3, 4, 5):
        _material(conn, item_id, TEXT)
    _patch_model(monkeypatch, _Provider(error=RuntimeError("down")))

    metrics = ScreenWriteupMaterialsStep().run(
        _ctx(conn, writeup_screen_concurrency=2, writeup_screen_limit=10)
    ).metrics

    assert metrics["provider_down"] == 1
    assert metrics["processed"] == 2
    assert metrics["remaining"] == 3
    assert store.stats(conn)["screened"] == 0


# ---------------------------------------------------------------- 增量与幂等

def test_second_run_screens_nothing(monkeypatch) -> None:
    """跑两遍第二遍 0 新增 —— 这是 T1.3 的验收条件。"""
    conn = _conn()
    _material(conn, 1, TEXT)
    _material(conn, 2, NO_CODE)
    provider = _Provider()
    _patch_model(monkeypatch, provider)
    step = ScreenWriteupMaterialsStep()

    first = step.run(_ctx(conn)).metrics
    second = step.run(_ctx(conn)).metrics

    assert first["pending"] == 2
    assert first["written"] == 2
    assert second["pending"] == 0
    assert second["written"] == 0
    assert provider.calls == 1, "第二遍一次模型都不该调"


def test_ids_alone_do_not_rescreen_but_force_does(monkeypatch) -> None:
    conn = _conn()
    _material(conn, 7, TEXT)
    provider = _Provider()
    _patch_model(monkeypatch, provider)
    step = ScreenWriteupMaterialsStep()
    step.run(_ctx(conn))

    assert step.run(_ctx(conn, writeup_screen_ids=[7])).metrics["pending"] == 0
    forced = step.run(_ctx(conn, writeup_screen_ids=[7], writeup_screen_force=True)).metrics
    assert forced["pending"] == 1
    assert provider.calls == 2


def test_budget_stops_between_chunks_and_leaves_the_rest(monkeypatch) -> None:
    conn = _conn()
    for item_id in (1, 2, 3, 4):
        _material(conn, item_id, TEXT)
    _patch_model(monkeypatch, _Provider())

    metrics = ScreenWriteupMaterialsStep().run(
        _ctx(conn, writeup_screen_concurrency=1, writeup_screen_budget_seconds=0)
    ).metrics

    assert metrics["budget_exhausted"] == 1
    assert metrics["processed"] == 1
    assert metrics["remaining"] == 3
    assert store.pending_materials(
        conn, rule_version=screener_rules.SCREENER_VERSION
    ), "没轮到的素材必须还在队列里"


# ---------------------------------------------------------------- 落盘方式

class _CountingConnection(sqlite3.Connection):
    commits = 0

    def commit(self) -> None:
        type(self).commits += 1
        return super().commit()


def test_rows_are_committed_in_batches_not_only_at_the_end() -> None:
    """按批 flush: 被杀只丢当前这一批, 而不是整轮白跑(T1.2 实测丢过 16 条)。"""
    _CountingConnection.commits = 0
    conn = sqlite3.connect(":memory:", factory=_CountingConnection)
    conn.row_factory = sqlite3.Row
    init_db(conn)
    for item_id in range(1, 7):
        _material(conn, item_id, NO_CODE)
    _CountingConnection.commits = 0

    metrics = ScreenWriteupMaterialsStep().run(
        _ctx(conn, writeup_screen_flush=2, writeup_screen_concurrency=1)
    ).metrics

    assert metrics["written"] == 6
    assert _CountingConnection.commits >= 3, "6 条 + 每 2 条一次 flush, 提交次数应明显多于 1"


# ---------------------------------------------------------------- 接线

def test_step_model_profile_matches_the_screener() -> None:
    """步骤上写的是字面量(为了不在导入时拉起模型路由), 必须和 screener 的对上。"""
    assert MODEL_PROFILE == screener.MODEL_PROFILE
    assert ScreenWriteupMaterialsStep().model_profile == screener.MODEL_PROFILE


def test_pipeline_is_registered() -> None:
    from ai4sec_platform.pipelines.registry import default_registry

    definition = default_registry().get("capabilities.writeup_repro_prescreen")
    assert definition.domain == "capabilities"
    assert [step.name for step in definition.steps] == ["screen_writeup_materials"]
