"""T2.1 / T2.3:复现任务表 —— 幂等、状态机、结论配对。

这一层错了不会报错, 只会让统计变得好看而没意义:

- 同一素材建两次任务 ⇒ 两个容器抢同一份代码, 结论互相覆盖;
- 状态随便改 ⇒ 库里“running”一堆, 实际一个都没在跑;
- ``cannot_repro`` 和 ``failed`` 混着记 ⇒ “原文不可复现”被读成“我们做不出来”。
"""
from __future__ import annotations

import sqlite3

import pytest

from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities.writeup_repro import screener, store, tasks
from ai4sec_platform.domains.capabilities.writeup_repro.screener_rules import screen_rules

TEXT = """# foo 攻击

影响 foo 1.2.3, 仓库 https://github.com/acme/foo

```bash
curl -s http://127.0.0.1:8080/admin
```

打成功后拿到 200。
"""


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def _candidate(material_id: int = 1, *, screenable: bool = True) -> dict:
    rule = screen_rules(TEXT, title="foo")
    result = {
        "is_writeup": True,
        "has_poc": True,
        "poc_lang": "shell",
        "poc_code": "curl -s http://127.0.0.1:8080/admin",
        "target_kind": "oss_repo" if screenable else "unknown",
        "target_repo": "https://github.com/acme/foo" if screenable else "",
        "target_version": "1.2.3" if screenable else "",
        "target_cve": "",
        "env_hint": "linux",
        "claimed_effect": "拿到 200",
        "evidence_quote": "打成功后拿到 200。",
        "confidence": 0.9,
    }
    return screener.build_candidate(
        material_id, "2026-11-11T00:00:00Z", {"rule": rule, "result": result, "text": TEXT, "title": "foo", "url": ""},
    )


@pytest.fixture()
def conn() -> sqlite3.Connection:
    return _conn()


# ---------------------------------------------------------------- 建任务

def test_create_task_copies_the_screening_conclusion(conn) -> None:
    store.upsert_candidate(conn, _candidate(7))
    task, created = tasks.create_task(conn, 7, created_by="alice")

    assert created is True
    assert task["material_id"] == 7
    assert task["status"] == "pending"
    assert task["claim"] == "拿到 200"
    assert task["target_repo"] == "github:acme/foo"
    assert task["target_version"] == "1.2.3"
    assert task["created_by"] == "alice"


def test_create_task_is_idempotent(conn) -> None:
    """同一素材点两次“复现”不该出现两条并行任务。"""
    store.upsert_candidate(conn, _candidate(8))
    first, created_first = tasks.create_task(conn, 8)
    second, created_second = tasks.create_task(conn, 8)

    assert (created_first, created_second) == (True, False)
    assert first["id"] == second["id"]
    assert conn.execute("SELECT COUNT(*) FROM writeup_repro_tasks").fetchone()[0] == 1


def test_create_task_refuses_unfresh_material(conn) -> None:
    """没有预筛结论 = 不知道它值不值得跑, 不能凭“有人点了”就建任务。"""
    with pytest.raises(ValueError, match="还没有预筛结论"):
        tasks.create_task(conn, 404)


def test_create_task_refuses_rejected_material(conn) -> None:
    store.upsert_candidate(conn, _candidate(9, screenable=False))
    with pytest.raises(ValueError, match="不可复现"):
        tasks.create_task(conn, 9)


# ---------------------------------------------------------------- 状态机

def _to_running(conn, task_id: int = 1) -> None:
    tasks.set_spec(conn, task_id, {"claim": "c", "target": {"kind": "oss_repo", "repo": "github:acme/foo"}})
    tasks.transition(conn, task_id, "queued")
    tasks.transition(conn, task_id, "running")


def test_happy_path(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    task = tasks.set_spec(conn, task["id"], {"claim": "c", "target": {"kind": "oss_repo", "repo": "github:acme/foo"}})
    assert task["status"] == "spec_ready" and task["spec_source"] == "llm"
    tasks.transition(conn, task["id"], "queued")
    final = tasks.transition(conn, task["id"], "running", verdict="")
    assert final["status"] == "running"
    done = tasks.transition(conn, task["id"], "success")
    assert done["verdict"] == "success" and done["failure_reason"] == ""
    assert done["finished_at"], "终态必须留时间戳, 否则跑多久只能靠 updated_at 猜"


def test_pending_cannot_jump_straight_to_running(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    with pytest.raises(ValueError, match="不是允许的迁移"):
        tasks.transition(conn, task["id"], "running")


def test_terminal_state_is_final(conn) -> None:
    """已完成的任务不许改回 running —— 结论是上一次的, 证据会被这一次覆盖。"""
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    _to_running(conn, task["id"])
    tasks.transition(conn, task["id"], "success")
    with pytest.raises(ValueError, match="已是终态"):
        tasks.transition(conn, task["id"], "running")


def test_cannot_repro_is_only_for_the_article(conn) -> None:
    """``cannot_repro`` 只归因于原文。环境起不来记这里, 就等于把我们的锅甩给作者。"""
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    _to_running(conn, task["id"])
    with pytest.raises(ValueError, match="只允许 failure_reason"):
        tasks.transition(conn, task["id"], "cannot_repro", failure_reason="env_error")


def test_version_mismatch_is_a_valid_cannot_repro(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    _to_running(conn, task["id"])
    done = tasks.transition(conn, task["id"], "cannot_repro", failure_reason="version_mismatch")
    assert done["verdict"] == "cannot_repro" and done["failure_reason"] == "version_mismatch"


def test_success_must_not_carry_a_failure_reason(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    _to_running(conn, task["id"])
    with pytest.raises(ValueError, match="failure_reason"):
        tasks.transition(conn, task["id"], "success", failure_reason="env_error")


def test_non_terminal_states_cannot_carry_a_conclusion(conn) -> None:
    """跑到一半就写 verdict, 等于把结论提前写了一半。"""
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    tasks.set_spec(conn, task["id"], {"claim": "c"})
    with pytest.raises(ValueError, match="不是结论状态"):
        tasks.transition(conn, task["id"], "queued", verdict="success")


def test_cancel_from_active_state(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    cancelled = tasks.cancel(conn, task["id"])
    assert cancelled["status"] == "cancelled" and cancelled["verdict"] == ""


def test_cancel_after_finish_is_rejected(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    _to_running(conn, task["id"])
    tasks.transition(conn, task["id"], "success")
    with pytest.raises(ValueError, match="已是终态"):
        tasks.cancel(conn, task["id"])


def test_transition_carries_evidence_and_recipe(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    _to_running(conn, task["id"])
    done = tasks.transition(
        conn, task["id"], "success",
        container_name="wr-1", duration_seconds=42, tool_calls=7,
        evidence={"probe": "exit_code == 0"}, recipe={"image": "ubuntu:24.04"},
    )
    assert done["container_name"] == "wr-1" and done["duration_seconds"] == 42
    assert done["evidence_json"]["probe"] == "exit_code == 0"
    assert done["recipe_json"]["image"] == "ubuntu:24.04"


def test_transition_rejects_unknown_field(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    with pytest.raises(ValueError, match="不支持更新字段"):
        tasks.transition(conn, task["id"], "queued", created_by="mallory")


# ---------------------------------------------------------------- 查询与统计

def test_list_total_is_not_the_page_length(conn) -> None:
    """卡片上的“共 N 条”必须是 COUNT, 不是当前页几条(2026-09-11 那批 1351 条的教训)。"""
    for material_id in range(1, 6):
        store.upsert_candidate(conn, _candidate(material_id))
        tasks.create_task(conn, material_id)
    items, total = tasks.list_tasks(conn, limit=2)
    assert len(items) == 2 and total == 5


def test_spec_failed_is_its_own_terminal_state(conn) -> None:
    """"建不出 spec"既不是原文不可复现, 也不是跑失败 —— 单列, 否则统计里全是我们的锅。"""
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    closed = tasks.transition(conn, task["id"], "spec_failed", log="连续 3 次引用对不上")
    assert closed["status"] == "spec_failed" and closed["verdict"] == ""
    with pytest.raises(ValueError, match="已是终态"):
        tasks.transition(conn, task["id"], "queued")


def test_spec_attempts_only_count_quality_failures(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    assert [tasks.bump_spec_attempt(conn, task["id"]) for _ in range(3)] == [1, 2, 3]
    assert tasks.get_task(conn, task["id"])["status"] == "pending"


def test_stats_keeps_our_fault_apart_from_theirs(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    store.upsert_candidate(conn, _candidate(2))
    first, _ = tasks.create_task(conn, 1)
    second, _ = tasks.create_task(conn, 2)
    _to_running(conn, first["id"])
    _to_running(conn, second["id"])
    tasks.transition(conn, first["id"], "cannot_repro", failure_reason="article_incomplete")
    tasks.transition(conn, second["id"], "failed", failure_reason="env_error")

    stats = tasks.stats(conn)
    assert stats["total"] == 2
    assert stats["by_verdict"] == {"cannot_repro": 1, "failed": 1}
    assert stats["by_failure_reason"] == {"article_incomplete": 1, "env_error": 1}
    assert stats["active"] == 0
