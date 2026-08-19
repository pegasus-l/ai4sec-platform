"""复现模块——cap-pipeline 评估完成后，调 opencode serve 做项目复现（clone+build+test）。

流程: 创建session → 发消息(让AI clone+build+test) → 轮询结果 → 写回DB
Task-aware 版本（2026-08-19）: 每次复现在 capability_repro_tasks 建 task 行，
实时写 log（进度心跳 + 完成全文），report_json 存 ReproReport 结构，
前端"复现验证"页（任务队列 + 实时日志 + 结果汇总）原样显示。

实时性说明: opencode serve 缓冲整个 agent 运行，完成后才返回；session 元数据
无增量文本。因此运行时推送的是"进度心跳"，完成后全文一次性落盘。
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from ai4sec_platform.pipelines.context import PipelineContext
from ai4sec_platform.pipelines.results import StepResult
from ai4sec_platform.db import repositories as repo


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    """每线程新开 DB 连接（sqlite 连接不跨线程共享）。"""
    from ai4sec_platform.db.session import connect

    conn = connect()
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# 前端 ReproTask status 词表: queued|running|success|partial|failed|timeout|stopped|cleaned
# payload repro_status 词表（与前端卡片 map 对齐）: candidate|in_progress|no_code|success|partial|failed|error
# ---------------------------------------------------------------------------
_PAYLOAD_ACTIVE_STATUSES = {"success", "succeeded", "partial", "failed", "in_progress", "error"}
_STATUS_TO_ITEM = {"success": "已复现", "partial": "部分复现", "failed": "复现失败", "error": "复现失败"}

# 停止协作标志（线程无法强杀，用 Event 在每个心跳检查点中止）
_STOP_FLAGS: dict[int, threading.Event] = {}


def stop_repro_task(task_id: int) -> None:
    ev = _STOP_FLAGS.get(task_id)
    if ev:
        ev.set()


def cleanup_repro_task(task_id: int) -> None:
    """新链路无容器/产物可清理；仅中止运行中的任务。"""
    stop_repro_task(task_id)


def _is_stopped(task_id: int) -> bool:
    ev = _STOP_FLAGS.get(task_id)
    return bool(ev and ev.is_set())


# ---------------------------------------------------------------------------
# HTTP primitives
# ---------------------------------------------------------------------------
def _headers(password: str) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if password:
        import base64

        cred = base64.b64encode(f"opencode:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {cred}"
    return headers


def _create_session(base_url: str, headers: dict[str, str], title: str) -> str:
    req = urllib.request.Request(
        f"{base_url}/session", method="POST", headers=headers,
        data=json.dumps({"title": title}).encode(),
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        session = json.loads(resp.read())
    session_id = session.get("id") or session.get("ID")
    if not session_id:
        raise RuntimeError("opencode serve: no session ID returned")
    return session_id


def _send_message(base_url: str, headers: dict[str, str], session_id: str, code_url: str, title: str, timeout: int) -> dict[str, Any]:
    prompt = (
        f"Please clone the repository at {code_url}, read the README, "
        f"install dependencies, run the build, and execute tests. "
        f"Report: 1) build success/failure 2) test results 3) key issues or caveats. "
        f"Be concise.\n"
        f"Note: this environment has NO Docker. If the project expects Docker/"
        f"docker-compose deployment, first try building and running the source "
        f"directly without Docker (pip/npm/yarn/make etc.). Only if Docker is the "
        f"only viable path, output FINAL_VERDICT PARTIAL and state clearly in the "
        f"report that the repository requires a Docker environment and cannot be "
        f"fully reproduced here.\n"
        f"At the very end output exactly one line: FINAL_VERDICT: SUCCESS, PARTIAL, or FAILURE. "
        f"(SUCCESS = clean build and tests pass; PARTIAL = builds/tests only after manual fixes "
        f"like creating missing stub files, or requires Docker; FAILURE = cannot build or run.)"
    )
    req = urllib.request.Request(
        f"{base_url}/session/{session_id}/message", method="POST", headers=headers,
        data=json.dumps({"messageID": f"msg-{int(time.time())}", "parts": [{"type": "text", "text": prompt}]}).encode(),
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _get_session_meta(base_url: str, headers: dict[str, str], session_id: str) -> dict[str, Any]:
    try:
        req = urllib.request.Request(f"{base_url}/session/{session_id}", headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def _extract_full_response(msg_data: dict[str, Any]) -> str:
    parts = msg_data.get("parts") or []
    text_parts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("type") == "text"]
    return "\n".join(text_parts)


def _detect_verdict(text: str) -> str:
    """三态判定 FINAL_VERDICT → success|partial|failed（结构化优先，关键词兜底）。"""
    text_lower = text.lower()
    for line in text_lower.splitlines():
        if "final_verdict" not in line:
            continue
        if "partial" in line:
            return "partial"
        if "failure" in line:
            return "failed"
        if "success" in line:
            return "success"
    success_markers = ["build succeeded", "build successful", "build complete", "build success", "successfully built", "build passed", "✓ build", "✓ all tests"]
    failure_markers = ["build failed", "build error", "compilation failed", "build failure", "❌", "error: build"]
    has_success = any(m in text_lower for m in success_markers)
    has_failure = any(m in text_lower for m in failure_markers)
    if has_failure:
        return "failed"
    if has_success:
        return "success"
    return "failed"


def _extract_test_results(text: str) -> str:
    lines = text.split("\n")
    test_lines = [l for l in lines if any(k in l.lower() for k in ["test", "pass", "fail", "skip", "coverage"])]
    return "\n".join(test_lines[:20]) if test_lines else "No test results found in response"


# ---------------------------------------------------------------------------
# Task-aware DB helpers（每操作新开连接，线程安全）
# ---------------------------------------------------------------------------
def _append_log(task_id: int, line: str) -> None:
    conn = _connect()
    try:
        repo.append_repro_log(conn, task_id=task_id, line=line)
        conn.commit()
    finally:
        conn.close()


def _update_task(task_id: int, **fields: Any) -> None:
    conn = _connect()
    try:
        repo.update_repro_task(conn, task_id=task_id, **fields)
        conn.commit()
    finally:
        conn.close()


def _write_payload(item_id: int, repro_status: str, repro_result: dict[str, Any], item_status: str | None = None) -> None:
    conn = _connect()
    try:
        item = repo.get_domain_item(conn, "capabilities", item_id)
        if not item:
            return
        payload = dict(item.get("payload") or {})
        payload["repro_status"] = repro_status
        payload["repro_result"] = repro_result
        fields: dict[str, Any] = {"payload": payload}
        if item_status:
            fields["status"] = item_status
        repo.update_domain_item(conn, item_id=item_id, **fields)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def _run_task(task_id: int, item_id: int, code_url: str, title: str, timeout: int) -> None:
    """后台线程主体: 建会话 → 发消息(子线程) → 心跳 → 完成写全文/汇总/回写 payload。"""
    repro_url = _env("REPRO_API_URL", "http://repro:4096")
    password = _env("REPRO_PASSWORD", "")
    headers = _headers(password)
    session_id: str | None = None
    try:
        _update_task(task_id, status="running")
        _append_log(task_id, f"开始复现: {code_url}")
        _append_log(task_id, f"复现环境: opencode serve ({repro_url}) · 超时上限 {timeout}s")
        _write_payload(item_id, "in_progress", {"running": True, "started_at": _utc_now()})

        session_id = _create_session(repro_url, headers, f"repro-{task_id}: {title}")
        _append_log(task_id, f"已创建复现会话 {session_id}")

        result_box: dict[str, Any] = {}

        def _post() -> None:
            try:
                result_box["value"] = _send_message(repro_url, headers, session_id, code_url, title, timeout)
            except Exception as e:  # noqa: BLE001 - 线程内兜底
                result_box["error"] = e

        poster = threading.Thread(target=_post, daemon=True)
        poster.start()

        t0 = time.time()
        while poster.is_alive():
            if _is_stopped(task_id):
                _update_task(task_id, status="stopped", finished_at=_utc_now(), result="stopped by user")
                _append_log(task_id, "⏹ 已由用户停止")
                _write_payload(item_id, "candidate", {"stopped": True})
                return
            elapsed = int(time.time() - t0)
            line = f"[复现中] agent 正在克隆 / 构建 / 测试… (已等待 {elapsed}s)"
            meta = _get_session_meta(repro_url, headers, session_id)
            tokens = meta.get("tokens")
            if tokens:
                line += f" · tokens={tokens}"
            _append_log(task_id, line)
            time.sleep(15)

        if "error" in result_box:
            raise result_box["error"]

        msg_data = result_box["value"]
        full_response = _extract_full_response(msg_data)
        verdict = _detect_verdict(full_response)

        _append_log(task_id, f"[复现完成] 判定 {verdict.upper()}，全文报告:")
        for line in full_response.splitlines():
            _append_log(task_id, line)

        summary = full_response.strip()[:400]
        report: dict[str, Any] = {
            "status": verdict,
            "summary": summary,
            "level": "auto",
            "project_type": "auto",
            "environment": {"provider": "opencode-serve", "session_id": session_id},
            "steps": [],
        }
        _update_task(
            task_id,
            status=verdict,
            finished_at=_utc_now(),
            result=full_response[:10000],
            report_json=json.dumps(report, ensure_ascii=False),
        )
        _write_payload(item_id, verdict, {
            "verdict": verdict,
            "summary": summary,
            "session_id": session_id,
            "build_success": verdict == "success",
            "test_results": _extract_test_results(full_response),
            "report_text": full_response[:2000],
        }, item_status=_STATUS_TO_ITEM.get(verdict))
    except Exception as e:  # noqa: BLE001
        emsg = str(e)
        if "timed out" in emsg.lower():
            emsg = f"timed out after {timeout}s (REPRO_API_URL={repro_url})"
            _update_task(task_id, status="timeout", finished_at=_utc_now(), result=emsg[:10000])
            _append_log(task_id, f"✗ {emsg}")
            _write_payload(item_id, "error", {"error": emsg}, item_status="复现失败")
        else:
            _update_task(task_id, status="failed", finished_at=_utc_now(), result=emsg[:10000])
            _append_log(task_id, f"✗ 复现异常: {emsg}")
            _write_payload(item_id, "error", {"error": emsg}, item_status="复现失败")


def start_repro_task(conn: sqlite3.Connection, *, item_id: int, code_url: str, trigger: str = "manual", timeout: int = 1200) -> tuple[int, threading.Thread]:
    """建 task 行并后台跑复现（API 按钮/管道共用）。返回 (task_id, thread)。
    thread.join() 等完成；API 侧忽略 thread 即可（daemon 继续跑）。"""
    task_id = repo.create_repro_task(conn, item_id=item_id, repo_url=code_url, trigger=trigger)
    conn.commit()
    _STOP_FLAGS[task_id] = threading.Event()

    title = str(code_url).rstrip("/").split("/")[-1]
    thread = threading.Thread(target=_run_task, args=(task_id, item_id, code_url, title, timeout), daemon=True, name=f"repro-{task_id}")
    thread.start()
    return task_id, thread


def run_repro_sync(conn: sqlite3.Connection, *, item_id: int, code_url: str, trigger: str = "manual", timeout: int = 1200) -> str:
    """同步跑一条复现并返回最终 task status（供管道 step 使用）。"""
    task_id, thread = start_repro_task(conn, item_id=item_id, code_url=code_url, trigger=trigger, timeout=timeout)
    thread.join(timeout=timeout + 120)
    task = repo.get_repro_task(conn, task_id)
    return (task or {}).get("status", "failed")


@dataclass
class TriggerReproStep:
    """评估完成后，对"待复现验证"的条目触发 opencode serve 复现（task-aware）。"""
    name: str = "trigger_repro"
    step_type: str = "repro"

    def run(self, context: PipelineContext) -> StepResult:
        timeout = int(context.params.get("repro_timeout_seconds", 1200))
        limit = int(context.params.get("repro_limit", 1))
        target_id = context.params.get("repro_item_id")

        # 直接扫库取候选:待复现验证 + 有 code_url + 尚未复现/复现中
        if target_id:
            row = repo.get_domain_item(context.conn, "capabilities", int(target_id))
            candidates = [row] if row else []
        else:
            items = repo.list_domain_items(context.conn, "capabilities", item_type="capability", status="待复现验证", limit=10000)
            candidates = [
                it for it in items
                if (it.get("payload") or {}).get("code_url")
                and (it.get("payload") or {}).get("repro_status") not in _PAYLOAD_ACTIVE_STATUSES
            ][:limit]

        triggered = 0
        succeeded = 0
        failed = 0

        for item in candidates:
            payload = item.get("payload") or {}
            code_url = payload.get("code_url") or ""
            status = item.get("status") or ""
            item_id = item.get("id")

            if status != "待复现验证" or not code_url:
                continue

            try:
                task_status = run_repro_sync(
                    context.conn, item_id=item_id, code_url=code_url,
                    trigger="pipeline", timeout=timeout,
                )
                triggered += 1
                if task_status == "success":
                    succeeded += 1
                else:
                    failed += 1
            except Exception as e:  # noqa: BLE001
                emsg = str(e)
                if "timed out" in emsg.lower():
                    emsg = f"timed out after {timeout}s (REPRO_API_URL={_env('REPRO_API_URL', 'http://repro:4096')})"
                conn = _connect()
                try:
                    item_row = repo.get_domain_item(conn, "capabilities", item_id)
                    if item_row:
                        p = dict(item_row.get("payload") or {})
                        p["repro_result"] = {"error": emsg}
                        p["repro_status"] = "error"
                        repo.update_domain_item(conn, item_id=item_id, status="复现失败", payload=p)
                        conn.commit()
                finally:
                    conn.close()
                failed += 1

        return StepResult(metrics={"triggered": triggered, "succeeded": succeeded, "failed": failed})
