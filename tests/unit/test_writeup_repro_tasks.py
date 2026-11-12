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


# ---------------------------------------------------------------- 重跑: (material_id, attempt)

def _finished(conn, material_id: int = 1, *, verdict: str = "partial") -> dict:
    """建一条跑到终态的任务, 以便测重跑。"""
    store.upsert_candidate(conn, _candidate(material_id))
    task, _ = tasks.create_task(conn, material_id)
    tasks.set_spec(conn, task["id"], {
        "claim": "c",
        "target": {"kind": "oss_repo", "repo": "github:acme/foo"},
        "steps": [{"run": "python3 poc.py"}],
        "probe": {"cmd": "python3 poc.py", "success_signal": "exit_code == 0"},
    })
    tasks.transition(conn, task["id"], "queued")
    tasks.transition(conn, task["id"], "running")
    tasks.transition(conn, task["id"], verdict,
                     failure_reason="probe_not_matched" if verdict == "partial" else "")
    return tasks.get_task(conn, task["id"])


def test_rerun_opens_a_new_attempt_and_keeps_the_old_row(conn) -> None:
    """重跑的硬约束: 上一遍那行**一个字都不改**。

    会话跑完就 404(opencode 不留 transcript), 把旧行重置成 running 等于把唯一一次真实执行
    的记录冲掉, "上一遍 partial、这一遍 success"这个事实也就没了。
    """
    first = _finished(conn, 1)
    before = tasks.get_task(conn, first["id"])

    second = tasks.rerun(conn, first["id"], created_by="alice")

    assert second["id"] != first["id"]
    assert second["material_id"] == first["material_id"] == 1
    assert second["attempt"] == 2
    assert second["trigger"] == "rerun"
    assert second["status"] == "spec_ready", "上一遍有 spec ⇒ 新行可以直接跑, 不必重新生成"
    assert second["spec_json"]["probe"]["cmd"] == "python3 poc.py"
    assert second["created_by"] == "alice"
    assert tasks.get_task(conn, first["id"]) == before, "旧行连 updated_at 都不该动"
    assert "重跑自任务 #%d" % first["id"] in second["log"]


def test_rerun_chains_to_a_third_attempt(conn) -> None:
    first = _finished(conn, 1)
    second = tasks.rerun(conn, first["id"])
    tasks.transition(conn, second["id"], "queued")
    tasks.transition(conn, second["id"], "running")
    tasks.transition(conn, second["id"], "success")
    third = tasks.rerun(conn, second["id"])
    assert third["attempt"] == 3
    assert tasks.get_task_by_material(conn, 1)["id"] == third["id"], "取当前这一遍 = 最新一遍"


def test_rerun_refuses_a_task_that_has_not_finished(conn) -> None:
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    with pytest.raises(ValueError, match="只有终态任务能重跑"):
        tasks.rerun(conn, task["id"])


def test_rerun_carries_no_spec_if_there_was_none(conn) -> None:
    """上一遍是 spec_failed ⇒ 新行回到 pending, 重跑要重新生成 spec, 不假装能跑。"""
    store.upsert_candidate(conn, _candidate(1))
    task, _ = tasks.create_task(conn, 1)
    tasks.transition(conn, task["id"], "spec_failed")
    again = tasks.rerun(conn, task["id"])
    assert again["status"] == "pending" and again["attempt"] == 2


def test_two_attempts_of_the_same_material_cannot_collide(conn) -> None:
    """唯一键是 (material_id, attempt): 同 attempt 撞键, 不同 attempt 放行。"""
    first = _finished(conn, 1)
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO writeup_repro_tasks (material_id, attempt, created_at)"
            " VALUES (?, ?, 'x')", (1, first["attempt"]),
        )


def test_migration_rebuilds_the_old_single_column_unique(conn) -> None:
    """老库(UNIQUE(material_id))要被 init_db 重建成 (material_id, attempt), 且数据不丢。

    列级 UNIQUE 建的是自动索引, 删不掉, 只能重建表 —— 这条测试盯的是"重建完列还在、
    行还在、还能插第二遍"。
    """
    conn.executescript(
        """
        DROP TABLE writeup_repro_tasks;
        CREATE TABLE writeup_repro_tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            material_id INTEGER NOT NULL UNIQUE,
            claim       TEXT NOT NULL DEFAULT '',
            status      TEXT NOT NULL DEFAULT 'pending',
            verdict     TEXT NOT NULL DEFAULT '',
            created_at  TEXT NOT NULL
        );
        INSERT INTO writeup_repro_tasks (material_id, claim, created_at) VALUES (42, '老行', 'x');
        CREATE INDEX IF NOT EXISTS idx_wrt_status ON writeup_repro_tasks(status, id);
        """
    )
    init_db(conn)

    cols = [r[1] for r in conn.execute("PRAGMA table_info(writeup_repro_tasks)").fetchall()]
    assert "attempt" in cols
    row = conn.execute("SELECT material_id, attempt, claim FROM writeup_repro_tasks").fetchone()
    assert tuple(row) == (42, 1, "老行"), "存量行一律算第 1 遍"
    conn.execute(
        "INSERT INTO writeup_repro_tasks (material_id, attempt, created_at) VALUES (42, 2, 'x')"
    )
    indexes = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='writeup_repro_tasks'"
    ).fetchall()}
    assert {"idx_wrt_status", "idx_wrt_verdict", "idx_wrt_material"} <= indexes, (
        "重建表时索引必须重新建在新表上(名字被旧表占着会让 CREATE INDEX IF NOT EXISTS 静默跳过)"
    )
