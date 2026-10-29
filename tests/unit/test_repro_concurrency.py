"""复现并发上限单元测试(2026-10-29)。

背景: 复现容器 6G → 10G 仍被 OOM。一条复现要编译、装依赖、起服务、有时还要跑无头浏览器,
实测吃 1-2G; 同时跑三四条就顶到 cgroup 上限, 内核挑中的常是 PID1 的 opencode ——
整个沙箱重启, 所有复现页 502。所以给"真正在跑"的复现加一道进程内闸门:
uvicorn 单 worker, 进程里的信号量即全局上限; 超出的任务**留在 queued**(页面显示「排队中」),
拿到名额才开跑。

这里锁住三件事:
  1. 同时在跑的复现数不超过 REPRO_MAX_CONCURRENT(默认 2), 但排队的任务最终都会跑;
  2. 排队期间被「停止」的任务不会白开一个会话, 直接落 stopped;
  3. 看门狗不把"还在排队、线程活着"的任务当僵尸回收(它的 created_at 里含着排队时间)。
"""
from __future__ import annotations

import threading
import time

from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.pipelines.steps import repro as repro_step


def _db():
    conn = connect()
    init_db(conn)
    return conn


def test_concurrency_cap_holds_extra_tasks_in_queue(monkeypatch) -> None:
    """5 条任务、上限 2: 任一时刻最多 2 条在跑, 而且 5 条最后都跑过。"""
    state = {"running": 0, "peak": 0, "started": []}
    lock = threading.Lock()
    logs: list[tuple[int, str]] = []

    def fake_body(task_id, item_id, code_url, title, timeout):
        with lock:
            state["running"] += 1
            state["peak"] = max(state["peak"], state["running"])
            state["started"].append(task_id)
        time.sleep(0.15)
        with lock:
            state["running"] -= 1

    monkeypatch.setattr(repro_step, "_MAX_CONCURRENT_REPRO", 2)
    monkeypatch.setattr(repro_step, "_REPRO_SLOTS", threading.BoundedSemaphore(2))
    monkeypatch.setattr(repro_step, "_run_task_body", fake_body)
    monkeypatch.setattr(repro_step, "_is_stopped", lambda task_id: False)
    monkeypatch.setattr(repro_step, "_update_task", lambda task_id, **fields: None)
    monkeypatch.setattr(repro_step, "_append_log", lambda task_id, line: logs.append((task_id, line)))

    threads = [
        threading.Thread(target=repro_step._run_task, args=(tid, 1, "https://github.com/o/r", "r", 10))
        for tid in range(5)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)

    assert state["peak"] == 2, state
    assert sorted(state["started"]) == [0, 1, 2, 3, 4]
    # 排队的 3 条各留一行「排队中」, 用户在前端看得到为什么没动
    queued = [line for _, line in logs if "排队中" in line]
    assert len(queued) == 3, logs


def test_stop_while_queued_never_starts_body(monkeypatch) -> None:
    """名额被占住时点「停止」: 名额空出来后也不该开跑, 直接落 stopped。"""
    slots = threading.BoundedSemaphore(1)
    slots.acquire()  # 模拟"已经有一条在跑"
    monkeypatch.setattr(repro_step, "_MAX_CONCURRENT_REPRO", 1)
    monkeypatch.setattr(repro_step, "_REPRO_SLOTS", slots)
    called: list[tuple] = []
    updates: list[tuple[int, dict]] = []
    monkeypatch.setattr(repro_step, "_run_task_body", lambda *a: called.append(a))
    monkeypatch.setattr(repro_step, "_update_task", lambda task_id, **fields: updates.append((task_id, fields)))
    monkeypatch.setattr(repro_step, "_append_log", lambda task_id, line: None)

    stop = threading.Event()
    monkeypatch.setitem(repro_step._STOP_FLAGS, 7, stop)
    worker = threading.Thread(target=repro_step._run_task, args=(7, 1, "https://github.com/o/r", "r", 10))
    worker.start()
    try:
        time.sleep(0.2)
        assert worker.is_alive() and not called  # 还在排队
        stop.set()      # 用户在队列里点了停止
        slots.release()  # 前一条跑完, 名额空出来
        worker.join(5)
    finally:
        stop.set()

    assert not called, "排队期间已停止的任务不该再开会话"
    assert updates and updates[-1][1]["status"] == "stopped"


def test_watchdog_does_not_reap_queued_task_whose_thread_is_alive(monkeypatch) -> None:
    """排队任务的 created_at 里含着排队时间, 不能拿它当「agent 挂死」判死。"""
    conn = _db()
    item_id = repo.create_domain_item(
        conn, domain="capabilities", item_type="capability",
        title="django/django", status="待复现验证", payload={},
    )
    task_id = repo.create_repro_task(conn, item_id=item_id, repo_url="https://github.com/django/django")
    # 拨老到超过 timeout+grace+300 阈值: 若按「运行超时」判就会误杀
    conn.execute(
        "UPDATE capability_repro_tasks SET created_at = '2020-01-01T00:00:00+00:00' WHERE id = ?",
        (task_id,),
    )
    conn.commit()

    stop = threading.Event()
    runner = threading.Thread(target=stop.wait, name=f"repro-{task_id}", daemon=True)
    runner.start()
    try:
        assert repro_step.reap_stale_repro_tasks() == 0
        assert repo.get_repro_task(conn, task_id)["status"] == "queued"
    finally:
        stop.set()
        runner.join(2)
