"""能力评测(E1)API。

用例守的是"页面会读错"的那几处:
  · 没有 run 的条目被写成"评测失败"(应该写"尚未评测")
  · 执行位还没上线, 点一下就在库里留一条永远 running 的僵尸 run
  · 报表缺样本数/时间窗/caveats 也能被页面读走
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sqlite3
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ai4sec_platform.app.api import capability_eval as api
from ai4sec_platform.app.main import app
from ai4sec_platform.app.middleware import ASISSessionMiddleware, COOKIE_NAME
from ai4sec_platform.db.models import init_db
from ai4sec_platform.db.session import connect
from ai4sec_platform.domains.capabilities.eval import samples as S
from ai4sec_platform.domains.capabilities.eval import store

DIFF = """diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -1,5 +1,6 @@
 alpha
 beta
-VULN(x)
+SAFE(x)
+also_safe(x)
 gamma
 delta
"""
POST = "alpha\nbeta\nSAFE(x)\nalso_safe(x)\ngamma\ndelta"

PRE_ANSWER = json.dumps({"found": True, "findings": [{
    "file": "app.py", "function": "handler", "line_start": 3, "line_end": 3,
    "type_cwe": "CWE-78", "evidence": "stub"}]})
CLEAN_ANSWER = json.dumps({"found": False, "findings": []})


def _client() -> TestClient:
    """/api/* 由会话中间件把守(2026-10-31 起过期 cookie 一律 401)。
    这里按**应用实际使用的密钥**签一张 admin 票 —— 硬编码某个密钥会在
    别人配了 SEC_AI_SESSION_SECRET 的环境里静默失败。"""
    middleware = next(m for m in app.user_middleware if m.cls is ASISSessionMiddleware)
    secret = str(middleware.kwargs.get("secret") or "").encode()
    payload = base64.urlsafe_b64encode(json.dumps(
        {"username": "tester", "role": "admin", "expiresAt": time.time() + 600},
    ).encode()).rstrip(b"=").decode()
    signature = base64.urlsafe_b64encode(
        hmac.new(secret, payload.encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    return TestClient(app, cookies={COOKIE_NAME: f"v1.{payload}.{signature}"})


@pytest.fixture()
def conn() -> sqlite3.Connection:
    c = connect()          # 与 API 用的是同一个库(conftest 已把路径指到 tmp)
    init_db(c)
    yield c
    c.close()


def _item(conn: sqlite3.Connection, title: str, level: int | None = 4) -> int:
    cur = conn.execute(
        "INSERT INTO domain_items (domain, item_type, title, summary, payload_json, status,"
        " created_at, updated_at) VALUES ('capabilities','capability_item',?,'',?,'active',?,?)",
        (title, json.dumps({"repo": "acme/tool"}), "2026-11-02T00:00:00Z",
         "2026-11-02T00:00:00Z"),
    )
    item_id = int(cur.lastrowid)
    if level is not None:
        conn.execute(
            "INSERT INTO capability_eval_levels (item_id, e0_level, e0_method, e0_source,"
            " e0_verified_at, computed_at) VALUES (?,?,'contract','agent_only',?,?)",
            (item_id, level, "2026-11-02T00:00:00Z", "2026-11-02T00:00:00Z"),
        )
    conn.commit()
    return item_id


def _dataset(tmp_path: Path) -> Path:
    src = S.CaseSource(
        case_id=1, canonical_id="CVE-2026-1001", repo="acme/app", commit_sha="a" * 40,
        file_path="app.py", function="handler", line_start=3, line_end=3, cwe="CWE-78",
        published_at="2026-10-20", vuln_content="VULN(x)", patch_diff=DIFF,
    )
    S.build_dataset([src], lambda repo, ref, path: POST, tmp_path / "ds", limit=1)
    return tmp_path / "ds"


def _scored_run(conn, tmp_path) -> int:
    store.ingest_dataset(conn, _dataset(tmp_path))
    run_id = store.create_run(conn, item_id=1, repeats=3)
    rows = store.list_samples(conn)
    pre = next(r["sample_key"] for r in rows if r["polarity"] == "pre")
    post = next(r["sample_key"] for r in rows if r["polarity"] == "post")
    store.save_answers(conn, run_id, {pre: [PRE_ANSWER] * 3, post: [CLEAN_ANSWER] * 3})
    store.score_run(conn, run_id)
    return run_id


def test_categories_report_sample_count(conn, tmp_path):
    store.ingest_dataset(conn, _dataset(tmp_path))
    body = _client().get("/api/capabilities/eval/categories").json()
    assert body["runner_ready"] is False
    assert body["items"][0]["n_samples"] == 2


def test_tool_without_runs_says_not_evaluated(conn, tmp_path):
    _item(conn, "还没评测的工具")
    body = _client().get("/api/capabilities/eval/tools").json()
    assert body["total"] == 1
    assert body["items"][0]["latest_run"] is None      # 不是 "failed", 是"没评过"
    assert body["items"][0]["e0"]["level"] == 4


def test_tool_list_carries_metrics(conn, tmp_path):
    _item(conn, "已评测的工具")
    run_id = _scored_run(conn, tmp_path)
    body = _client().get("/api/capabilities/eval/tools").json()
    latest = body["items"][0]["latest_run"]
    assert latest["run_id"] == run_id and latest["status"] == "success"
    assert latest["metrics"]["locate_rate"]["value"] == 1.0
    assert latest["caveats"]


def test_tool_detail_keeps_boundaries_on_screen(conn, tmp_path):
    item_id = _item(conn, "已评测的工具")
    _scored_run(conn, tmp_path)
    body = _client().get(f"/api/capabilities/eval/tools/{item_id}").json()
    assert body["latest"]["metrics"]["n_samples"] == 2
    assert len(body["cannot_answer"]) >= 3
    verdicts = {r["polarity"]: r["verdict"] for r in body["latest"]["results"]}
    assert verdicts == {"pre": "strict_hit", "post": "true_negative"}


def test_unknown_item_is_404(conn):
    assert _client().get("/api/capabilities/eval/tools/999").status_code == 404


def test_run_detail_lists_per_sample_verdicts(conn, tmp_path):
    run_id = _scored_run(conn, tmp_path)
    body = _client().get(f"/api/capabilities/eval/runs/{run_id}").json()
    assert body["metrics"]["n_samples"] == 2
    assert len(body["results"]) == 2
    assert body["results"][0]["per_repeat"][0]["repeat"] == "r1"


def test_unknown_run_is_404(conn):
    assert _client().get("/api/capabilities/eval/runs/999").status_code == 404


def test_tool_list_leaves_out_non_web_items(conn):
    """E1 本期只覆盖 Web 条目(2026-11-02 拍板)。列表里混进非 Web 条目,
    页面上那句「非 Web 183 条不评」就成了假话。"""
    web = _item(conn, "Web 工具")
    conn.execute("UPDATE domain_items SET payload_json=? WHERE id=?",
                 (json.dumps({"repo": "a/web", "is_web": True}), web))
    unclassified = _item(conn, "尚未分类的工具", level=3)   # 没有 is_web 键 ⇒ 不挡
    non_web = _item(conn, "非 Web 工具", level=2)
    conn.execute("UPDATE domain_items SET payload_json=? WHERE id=?",
                 (json.dumps({"repo": "a/cli", "is_web": False}), non_web))
    conn.commit()

    items = _client().get("/api/capabilities/eval/tools").json()["items"]
    assert {i["item_id"] for i in items} == {web, unclassified}


def test_start_run_refuses_a_non_web_item(conn, tmp_path, monkeypatch):
    """列表里看不到、却能直接 POST 发起, 等于给边界说明留了个后门。"""
    monkeypatch.setattr(api, "RUNNER_READY", True)
    item_id = _item(conn, "非 Web 工具")
    conn.execute("UPDATE domain_items SET payload_json=? WHERE id=?",
                 (json.dumps({"repo": "a/cli", "is_web": False}), item_id))
    store.ingest_dataset(conn, _dataset(tmp_path))
    resp = _client().post("/api/capabilities/eval/run", json={"item_id": item_id})
    assert resp.status_code == 409 and "非 Web" in resp.text
    assert conn.execute("SELECT COUNT(*) FROM capability_eval_runs").fetchone()[0] == 0


def test_runner_ready_switch_is_env_driven_and_defaults_to_off(monkeypatch):
    """执行位是 `--profile eval` 单独起的, 打开时机与镜像版本无关。
    写死在代码里 ⇒ 每翻一次开关都要重建镜像 + 重启全栈(有窗口代价)。
    这里钉两件事: 不开变量时仍然是关的(默认行为不变), 变量取值只认白名单。"""
    import importlib

    for value, expected in (("1", True), ("true", True), ("on", True),
                            ("0", False), ("", False), ("no", False)):
        monkeypatch.setenv("EVAL_RUNNER_READY", value)
        assert importlib.reload(api).RUNNER_READY is expected, value
    monkeypatch.delenv("EVAL_RUNNER_READY")
    assert importlib.reload(api).RUNNER_READY is False


def test_start_run_is_refused_until_the_runner_exists(conn, tmp_path):
    item_id = _item(conn, "工具")
    store.ingest_dataset(conn, _dataset(tmp_path))
    resp = _client().post("/api/capabilities/eval/run", json={"item_id": item_id})
    assert resp.status_code == 503
    # 拒绝就不许留痕: 库里不该多出一条 running
    assert conn.execute("SELECT COUNT(*) FROM capability_eval_runs").fetchone()[0] == 0


def test_start_run_requires_e0_level(conn, tmp_path, monkeypatch):
    monkeypatch.setattr(api, "RUNNER_READY", True)
    item_id = _item(conn, "没有 E0 的工具", level=None)
    store.ingest_dataset(conn, _dataset(tmp_path))
    resp = _client().post("/api/capabilities/eval/run", json={"item_id": item_id})
    assert resp.status_code == 409


def test_start_run_creates_a_running_row_when_ready(conn, tmp_path, monkeypatch):
    monkeypatch.setattr(api, "RUNNER_READY", True)
    item_id = _item(conn, "工具")
    store.ingest_dataset(conn, _dataset(tmp_path))
    body = _client().post(
        "/api/capabilities/eval/run", json={"item_id": item_id, "repeats": 3}).json()
    assert body["status"] == "running" and body["n_samples"] == 2
    run = store.get_run(conn, body["run_id"])
    assert run["repeats"] == 3
    # 谁发起的要留痕(页面上看不出"是谁点的"是最常见的运营问题)
    assert run["budget_json"]["requested_by"] == "tester"
