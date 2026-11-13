"""T2 API:8 个端点 + OpenAPI 注册 + 错误口径。

端点是薄的一层, 但错误口径很关键: **模型挂了要 5xx 且一行不写**, 不能把自己的故障
写成 ``cannot_repro``。所以这里逐个锁住"什么情况返回什么"。
"""
from __future__ import annotations

import json
import sqlite3

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from ai4sec_platform.app.api import writeup_repro as api
from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.capabilities.writeup_repro import screener, store, tasks
from ai4sec_platform.domains.capabilities.writeup_repro import spec as spec_module
from ai4sec_platform.domains.capabilities.writeup_repro.screener_rules import screen_rules

ARTICLE = """# foo 管理接口越权

foo 1.2.3 的 /admin 没有鉴权, 任何人可读配置。

```bash
curl -s http://127.0.0.1:8080/admin
```
"""

SPEC = {
    "sufficient": True,
    "claim": "未鉴权的用户可读取配置",
    "claim_quote": "foo 1.2.3 的 /admin 没有鉴权, 任何人可读配置。",
    "target": {"kind": "oss_repo", "repo": "https://github.com/acme/foo", "ref": "1.2.3"},
    "steps": [{"run": "curl -s http://127.0.0.1:8080/admin", "expect": "返回配置",
               "source_quote": "curl -s http://127.0.0.1:8080/admin"}],
    "probe": {"cmd": "curl -s http://127.0.0.1:8080/admin", "success_signal": "stdout 包含 config"},
}


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_db(conn)
    return conn


def _request(username: str = "alice") -> Request:
    return Request({"type": "http", "method": "POST", "path": "/api/writeup-repro/tasks",
                    "state": {"user": {"username": username, "role": "admin"}}})


def _material(conn, material_id: int = 1) -> None:
    conn.execute(
        "INSERT INTO domain_items (id, domain, item_type, title, status, source, source_url, primary_date,"
        " payload_json, created_at, updated_at) VALUES (?, 'vulnerabilities', 'material', 'foo', 'active',"
        " 'src', 'http://blog/1', '2026-11-01', ?, 'now', 'now')",
        (material_id, json.dumps({"cleaned_text": ARTICLE})),
    )
    conn.commit()
    store.upsert_candidate(conn, screener.build_candidate(
        material_id, "2026-11-11T00:00:00Z",
        {
            "rule": screen_rules(ARTICLE, title="foo"),
            "result": {
                "is_writeup": True, "has_poc": True, "poc_lang": "shell",
                "poc_code": "curl -s http://127.0.0.1:8080/admin",
                "target_kind": "oss_repo", "target_repo": "https://github.com/acme/foo",
                "target_version": "1.2.3", "target_cve": "",
                "claimed_effect": "读到配置", "evidence_quote": "任何人可读配置。", "confidence": 0.9,
            },
            "text": ARTICLE, "title": "foo", "url": "http://blog/1",
        },
    ))


@pytest.fixture()
def conn() -> sqlite3.Connection:
    return _conn()


# ---------------------------------------------------------------- 注册

def test_all_routes_are_in_openapi() -> None:
    from ai4sec_platform.app.main import app

    paths = app.openapi()["paths"]
    for path in (
        "/api/writeup-repro/tasks",
        "/api/writeup-repro/tasks/{task_id}",
        "/api/writeup-repro/tasks/{task_id}/spec",
        "/api/writeup-repro/tasks/{task_id}/transition",
        "/api/writeup-repro/tasks/{task_id}/cancel",
        "/api/writeup-repro/stats",
    ):
        assert path in paths, path


def test_endpoints_require_a_session() -> None:
    """未鉴权一律 401 —— 由中间件统一兜, 新路由不需要各写一遍。"""
    from fastapi.testclient import TestClient

    from ai4sec_platform.app.main import app

    client = TestClient(app)
    for path in ("/api/writeup-repro/tasks", "/api/writeup-repro/stats"):
        assert client.get(path).status_code == 401, path


# ---------------------------------------------------------------- 任务

def test_create_is_idempotent_over_the_api(conn) -> None:
    _material(conn)
    body = api.CreateTaskBody(material_id=1)
    first = api.create_task(body, _request(), conn)
    second = api.create_task(body, _request("bob"), conn)

    assert first["created"] is True and second["created"] is False
    assert first["task"]["id"] == second["task"]["id"]
    assert first["task"]["created_by"] == "alice"


def test_create_rejects_unfresh_material(conn) -> None:
    with pytest.raises(HTTPException) as exc:
        api.create_task(api.CreateTaskBody(material_id=99), _request(), conn)
    assert exc.value.status_code == 400


def test_list_rejects_unknown_status(conn) -> None:
    with pytest.raises(HTTPException) as exc:
        api.list_tasks(status="whatever", verdict=None, material_id=None, limit=50, offset=0, conn=conn)
    assert exc.value.status_code == 400


def test_transition_endpoint_rejects_illegal_move(conn) -> None:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    with pytest.raises(HTTPException) as exc:
        api.transition_task(task["id"], api.TransitionBody(to_state="running"), conn)
    assert exc.value.status_code == 400


def test_cancel_endpoint(conn) -> None:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    assert api.cancel_task(task["id"], conn)["task"]["status"] == "cancelled"


# ---------------------------------------------------------------- spec

def _patch_generate(monkeypatch, outcome):
    monkeypatch.setattr(spec_module, "generate_spec", lambda material, candidate=None: {
        "status": "success", "provider": "fake", "model": "fake-1",
        "spec": outcome, "payload": {}, "text": ARTICLE, "title": "foo",
    } if outcome is not None else {
        "status": "error", "provider": "", "model": "", "spec": {}, "payload": {},
        "text": ARTICLE, "title": "foo", "reason": "HTTP 403",
    })


def test_generate_spec_moves_task_to_spec_ready(conn, monkeypatch) -> None:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    _patch_generate(monkeypatch, SPEC)

    result = api.generate_task_spec(task["id"], conn)["task"]
    assert result["status"] == "spec_ready" and result["spec_source"] == "llm"
    assert result["claim_quote"] == SPEC["claim_quote"]
    assert result["spec_json"]["steps"][0]["index"] == 1


def test_model_saying_insufficient_becomes_cannot_repro(conn, monkeypatch) -> None:
    """模型明确说原文没写清是**结论**, 返回 200 并把归因写成 article_incomplete。"""
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    _patch_generate(monkeypatch, {"sufficient": False, "insufficient_reason": "没写怎么编译"})

    result = api.generate_task_spec(task["id"], conn)["task"]
    assert result["status"] == "cannot_repro"
    assert result["failure_reason"] == "article_incomplete"
    assert result["log"] == "没写怎么编译"


def test_unverifiable_quotes_never_become_a_verdict(conn, monkeypatch) -> None:
    """引用对不上 → 502 + 重试, 绝不写成"原文不可复现"(同一条素材两次结果会不同)。"""
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    _patch_generate(monkeypatch, {**SPEC, "claim_quote": "作者说这里有个严重越权"})

    with pytest.raises(HTTPException) as exc:
        api.generate_task_spec(task["id"], conn)
    assert exc.value.status_code == 502
    stored = tasks.get_task(conn, task["id"])
    assert stored["status"] == "pending" and stored["verdict"] == "" and stored["spec_attempts"] == 1


def test_unusable_spec_writes_nothing(conn, monkeypatch) -> None:
    """spec 不成形(命令是占位符)是我们自己的问题 —— 502, 任务留在 pending 等下一轮。"""
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    _patch_generate(monkeypatch, {**SPEC, "probe": {"cmd": "...", "success_signal": "exit_code == 0"}})

    with pytest.raises(HTTPException) as exc:
        api.generate_task_spec(task["id"], conn)
    assert exc.value.status_code == 502
    assert tasks.get_task(conn, task["id"])["status"] == "pending"


def test_repeated_unbuildable_specs_close_as_our_problem(conn, monkeypatch) -> None:
    """连建三次都建不出 → spec_failed: 记成我们的问题, 不是原文的。"""
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    _patch_generate(monkeypatch, {**SPEC, "claim_quote": "作者说这里有个严重越权"})

    for _ in range(tasks.MAX_SPEC_ATTEMPTS - 1):
        with pytest.raises(HTTPException):
            api.generate_task_spec(task["id"], conn)
    closed = api.generate_task_spec(task["id"], conn)["task"]

    assert closed["status"] == "spec_failed" and closed["verdict"] == ""
    assert tasks.stats(conn)["by_status"]["spec_failed"] == 1


def test_model_outage_is_not_a_verdict(conn, monkeypatch) -> None:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    _patch_generate(monkeypatch, None)

    with pytest.raises(HTTPException) as exc:
        api.generate_task_spec(task["id"], conn)
    assert exc.value.status_code == 502
    assert tasks.get_task(conn, task["id"])["status"] == "pending"


def test_human_edit_marks_the_spec_as_human(conn) -> None:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    result = api.update_task_spec(task["id"], api.SpecBody(spec=SPEC), conn)["task"]
    assert result["status"] == "spec_ready" and result["spec_source"] == "human"


def test_human_edit_still_rejects_prose_signals(conn) -> None:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    bad = {**SPEC, "probe": {"cmd": "curl -s http://127.0.0.1:8080/admin", "success_signal": "服务起来了"}}
    with pytest.raises(HTTPException) as exc:
        api.update_task_spec(task["id"], api.SpecBody(spec=bad), conn)
    assert exc.value.status_code == 400


def test_stats_endpoint_counts_active_tasks(conn) -> None:
    _material(conn)
    api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)
    stats = api.task_stats(conn)
    assert stats["total"] == 1 and stats["active"] == 1


# ---------------------------------------------------------------- 重跑

def _finished_task(conn) -> dict:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    tasks.set_spec(conn, task["id"], SPEC, source="human")
    tasks.transition(conn, task["id"], "queued")
    tasks.transition(conn, task["id"], "running")
    return tasks.transition(conn, task["id"], "partial", failure_reason="probe_not_matched")


def test_run_on_a_finished_task_points_at_the_rerun_endpoint(conn) -> None:
    """终态不能再跑, 而且报错要把人指到正确的入口 —— 否则调用方只会反复点 /run。"""
    task = _finished_task(conn)
    with pytest.raises(HTTPException) as exc:
        api.run_task(task["id"], timeout=None, conn=conn)
    assert exc.value.status_code == 400
    assert f"/tasks/{task['id']}/rerun" in exc.value.detail


def test_rerun_endpoint_opens_the_next_attempt_and_starts_it(conn, monkeypatch) -> None:
    task = _finished_task(conn)
    launched: list[int] = []
    monkeypatch.setattr(api.executor, "start_task",
                        lambda task_id, timeout=None: launched.append(task_id) or True)

    out = api.rerun_task(_request("bob"), task["id"], start=True, timeout=600, conn=conn)

    assert out["rerun_of"] == task["id"]
    assert out["started"] is True and launched == [out["task"]["id"]]
    assert out["task"]["attempt"] == 2 and out["task"]["trigger"] == "rerun"
    assert out["task"]["created_by"] == "bob"
    assert tasks.get_task(conn, task["id"])["status"] == "partial", "上一遍的记录一个字都不改"


def test_rerun_endpoint_refuses_an_unfinished_task(conn) -> None:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    with pytest.raises(HTTPException) as exc:
        api.rerun_task(_request(), task["id"], start=False, timeout=None, conn=conn)
    assert exc.value.status_code == 400


# ---------------------------------------------------------------- 报告(T4.3)

def _terminal_task(conn, verdict: str = "partial", reason: str = "probe_not_matched") -> int:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    conn.execute("UPDATE writeup_repro_tasks SET spec_json = ? WHERE id = ?", (json.dumps(SPEC), task["id"]))
    conn.commit()
    tasks.transition(conn, task["id"], "queued")
    tasks.transition(conn, task["id"], "running")
    tasks.transition(
        conn, task["id"], verdict, verdict=verdict, failure_reason=reason,
        evidence={"commands": [], "probe": {"found": False, "matched": None}, "guard": {"allowed": True}},
    )
    return int(task["id"])


def _patch_report_model(monkeypatch, sections: dict | None) -> None:
    from ai4sec_platform.domains.capabilities.writeup_repro import report as report_module

    monkeypatch.setattr(report_module, "generate_model_sections", lambda payload: {
        "status": "success", "sections": sections, "provider": "fake", "model": "fake-1",
    } if sections is not None else {
        "status": "error", "sections": {}, "reason": "HTTP 403",
    })


def test_report_routes_are_registered() -> None:
    from ai4sec_platform.app.main import app

    paths = app.openapi()["paths"]
    assert "/api/writeup-repro/tasks/{task_id}/report" in paths
    assert "get" in paths["/api/writeup-repro/tasks/{task_id}/report"]
    assert "post" in paths["/api/writeup-repro/tasks/{task_id}/report"]


def test_report_is_404_until_it_is_generated(conn, monkeypatch) -> None:
    task_id = _terminal_task(conn)
    with pytest.raises(HTTPException) as exc:
        api.get_task_report(task_id, conn)
    assert exc.value.status_code == 404

    _patch_report_model(monkeypatch, {
        "attribution": {"side": "ours", "reason": "沙箱没起来", "evidence_refs": []},
        "root_cause": {}, "pattern": {}, "caveats": ["模型推断, 未核对"],
    })
    created = api.generate_task_report(task_id, regenerate=True, conn=conn)
    assert created["status"] == "ok"
    assert created["report"]["verdict"] == "partial"
    assert created["report"]["caveats"]

    again = api.get_task_report(task_id, conn)["report"]
    assert again["task_id"] == task_id


def test_report_generation_is_refused_on_a_running_task(conn) -> None:
    _material(conn)
    task = api.create_task(api.CreateTaskBody(material_id=1), _request(), conn)["task"]
    with pytest.raises(HTTPException) as exc:
        api.generate_task_report(task["id"], regenerate=True, conn=conn)
    assert exc.value.status_code == 400


def test_a_model_failure_returns_502_and_writes_nothing(conn, monkeypatch) -> None:
    """502 之后库里仍然是空的 —— 否则下一轮重试会读到半份报告。"""
    task_id = _terminal_task(conn)
    _patch_report_model(monkeypatch, None)

    with pytest.raises(HTTPException) as exc:
        api.generate_task_report(task_id, regenerate=True, conn=conn)
    assert exc.value.status_code == 502
    assert conn.execute("SELECT COUNT(*) FROM writeup_repro_reports").fetchone()[0] == 0
