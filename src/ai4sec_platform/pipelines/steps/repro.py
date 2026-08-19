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

# 平台对外访问链接: 用户打开复现 Web 界面的入口(ASIS 8091 → /insights/ rewrite → ai4sec → /repro-web/ → repro:8080)
_PLATFORM_WEB_ROOT = _env("PLATFORM_WEB_ROOT", "http://119.8.125.117:8091")
REPRO_WEB_URL = f"{_PLATFORM_WEB_ROOT}/insights/repro-web/"

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


_WEB_REPORT_EXAMPLE = """{
  "is_web": true/false,
  "status": "success|partial|failed",
  "summary": "一句话结论(中文)。若项目本身无 Web 界面, 明确说明它是什么类型、为什么没界面",
  "web_started": true/false,
  "web_framework": "如 Streamlit / Gradio / FastAPI / React+Vite; 无则填空",
  "start_command": "你启动服务的命令; 没启动填空",
  "verify": "curl 验证结果; 没验证填空",
  "project_type": "python|node|rust|go|web|其他",
  "core_workflow": {"goal": "核心用户价值", "mode": "real|mock", "verified": true/false, "result": "产物或失败阶段", "evidence": ["真实响应/产物摘要"]},
  "environment": {"language": "如 Python 3.12", "key_deps": ["关键依赖"]},
  "steps": [{"cmd": "关键命令", "ok": true/false, "note": "可选"}],
  "blockers": ["卡点; 若项目本身无Web界面, 在此说明"],
  "gotchas": ["踩坑"],
  "usage": {"what": "这个项目是干什么的(一两句话, 让没接触过的人看懂)", "how_to_use": "用户打开页面后怎么用(页面上有什么功能/怎么操作/API怎么调用)", "prerequisites": "使用前必须配置的东西(API key、后端服务、数据库等, 没有就留空)", "limitations": "当前状态下的限制(哪些功能不可用、需要额外条件等, 没有就留空)"}
}"""


def _build_repro_prompt(code_url: str, task_id: int) -> str:
    """Web 类复现 prompt(中文)——判断是否有 Web 界面 → 启动验证 → 核心可用性验收 → 输出标记包裹的结构化 JSON。"""
    return (
        f"你在一个隔离容器里(你是 root, 可自由装包), 目标是【把一个开源项目跑起来、确认环境可用、尽量跑出真实运行效果】。"
        f"仓库源码地址: {code_url}。请把它全新克隆到独立目录 /workspace/repo-{task_id} "
        f"(若该目录或 /workspace/repo 有上次残留, 先 rm -rf 再克隆), 严禁在残留目录上操作。"
        f"全程用中文说明你在做什么——每一步、每个命令、遇到的坑都简要写出来。\n\n"
        f"环境注意: 本环境没有 Docker、没有 GPU。Web 服务必须监听 0.0.0.0:8080 —— 平台已把对外路径 /repro-web/ 反代到容器内 8080, "
        f"用户可通过 http://<平台地址>:8091/insights/repro-web/ 直接打开该界面。"
        f"总预算约 18 分钟, 必须在 15-16 分钟前停止继续探索, 把已验证的事实整理成报告; 核心闭环验证后不要枚举非必要功能。\n\n"
        f"# 第零步(最重要): 先判断这个项目【本身】到底有没有 Web 界面\n"
        f"读 README、看项目结构, 判断它是否【自带】一个真正的 Web 应用/界面:\n"
        f"- 有真 Web 界面的标志: 项目里有前端代码(React/Vue/HTML 应用)、或用 streamlit/gradio/flask/fastapi 写的、"
        f"README 明确说\"启动后访问 localhost:xxxx 看界面/dashboard\"。\n"
        f"- ❌ 如果项目【本身没有】Web 界面(它是 CLI 工具、Python 库、研究代码、prompt/数据集合集等), "
        f"你【绝对不要】自己造一个网页(比如写个 Flask 把一堆 .md 文件列出来), 那样毫无价值。"
        f"直接如实报告: is_web=false、web_started=false, 在 summary 说清\"该项目本身没有 Web 界面, 它是 XX 类型\"。\n\n"
        f"# 如果确认项目自带 Web 界面, 才执行下面的启动流程\n"
        f"- 服务必须监听 0.0.0.0:8080(平台对外路径 /repro-web/ → 容器内 8080, 用户可访问)。"
        f"启动前若 8080 被上次任务残留进程占用: 【先】把自己的启动命令写入 /workspace/.repro-web/current.sh(这样看护进程即使在你切换期间拉起服务, 用的也是你的命令), "
        f"【再】找到残留进程 kill 掉(如 `fuser -k 8080/tcp` 或按端口查 PID), 【最后】启动你自己的服务并验证 200。\n"
        f"- 常见启动方式: Streamlit: `streamlit run xxx.py --server.address 0.0.0.0 --server.port 8080`; "
        f"Gradio: 设 server_name=\"0.0.0.0\", server_port=8080; Flask/FastAPI: `uvicorn main:app --host 0.0.0.0 --port 8080`; "
        f"Node/Vite/React: `--host 0.0.0.0 --port 8080` 或 PORT=8080; 前端项目先 npm install。\n"
        f"- 在【后台】启动(`setsid nohup ... &`, 用 setsid 脱离当前会话进程组, 否则会话结束服务会被清掉), "
        f"启动后【sleep 10 秒】等服务起来, 再 `curl -s http://localhost:8080`。"
        f"如果 curl 没响应, 最多等 30 秒重试 2-3 次, 仍不行就如实报告 web_started=false 并结束。"
        f"用项目【原有】的前端, 不要自己另写页面。\n"
        f"- 启动命令纪律: 先定位真正的应用根目录(如仓库是 backend/app/main.py, 必须先 cd backend 再运行); "
        f"不要用 --reload/hot reload; 后台启动后立刻记录 PID(`setsid nohup ... >/tmp/service.log 2>&1 & echo $! >/tmp/service.pid`), "
        f"需要停止重试时用 `kill $(cat /tmp/service.pid)`, 绝对不要用 pkill -f(会误杀当前 shell)。"
        f"启动成功且 curl 验证 200 后, 把【能独立重启服务】的启动命令写入 /workspace/.repro-web/current.sh(平台看护进程会在 8080 挂掉时用它自动拉起, 保证用户访问链接长期有效)。"
        f"current.sh 必须用 sh 可执行、含 cd 到正确目录的完整命令, 例如: `#!/bin/sh` + `cd /workspace/repo-{task_id} && setsid nohup python3 -m <模块> serve --port 8080 >> /tmp/service.log 2>&1 &`。\n"
        f"首次启动失败不能直接结束: 读服务日志、检查工作目录/模块路径/端口/依赖, 至少修正重试一次。"
        f"前后端分离项目: 后端按其真实目录启动到内部端口(如 8000), 前端最终监听 0.0.0.0:8080, 并确认前端 /api 代理指向已启动的后端。\n"
        f"- 写配置前检查项目实际配置加载逻辑(Pydantic env_file、dotenv、进程 cwd), 配置文件必须放在运行进程真正读取的位置; "
        f"启动后通过配置对象、进程环境或实际响应确认 provider/model 等关键配置已生效, 不能只确认文件存在。\n"
        f"- `curl http://localhost:8080` 只证明页面服务启动, 不能单独作为复现成功的依据。\n"
        f"- 如果页面需要登录/注册: 必须实际调用注册或登录 API 确认能进入受保护页面; "
        f"没有预置账号但支持注册就创建专用 Demo 账号(不要用真实个人账号), 并把账号密码写进 usage.prerequisites; "
        f"注册不可用就找安全演示入口, 不能把用户留在登录页。\n\n"
        f"# 核心可用性验收(必须执行, 禁止\"首页 200 = 复现成功\")\n"
        f"- 读 README 和页面功能, 先一句话定义该项目最核心的用户价值与最短操作闭环。\n"
        f"- 至少实际完成一条超越登录和普通 CRUD 的核心业务链(如 AI 平台真实调用一次 AI 生成; 扫描器提交目标并拿到扫描结果; "
        f"分析工具导入样例并产出报告)。只创建账号、创建 Project、打开空 Dashboard 都不算。\n"
        f"- 前后端分离或多目录项目必须确认配置文件放在【实际进程读取的位置】, 并从运行中进程/生成结果验证配置已生效, 不能因为写过 .env 就声称启用。"
        f"若项目支持 mock, 必须区分 mock 输出与真实能力输出。\n"
        f"- 核心链依赖 LLM/API/数据库时, 必须检查真实 provider/model、响应内容、错误信息, 不能只看 HTTP 状态码。"
        f"核心 LLM 阶段超时/JSON 解析失败/schema 校验失败时不要立刻判失败: 先读错误详情, 优先降低 temperature、启用 JSON/structured-output 模式(若支持), "
        f"对同一阶段至少重试 2 次; 重试成功以成功产物为最终结论, 早先失败记入 gotchas; 全部失败才报 partial/failed。\n"
        f"- status 定义: success=核心业务链完整跑通且结果可用; partial=页面和部分功能可用但核心链仅部分跑通、用 mock、超时或关键阶段失败; "
        f"failed=页面不可用或核心入口完全无法执行。未执行核心业务链不得报 success。"
        f"core_workflow.mode 必须区分 real/mock, 用 mock/fixture/静态占位只能报 partial。\n"
        f"- 检查关键页面入口是否真实可点击; 核心路由/API 可用但页面无可发现入口时, 允许做最小导航修复(如加\"进入项目\"按钮), "
        f"但不得重写业务功能, 并必须在 gotchas 和 steps 中记录修改。\n\n"
        f"# 最后必须输出结构化报告(用标记包裹, JSON 必须合法, status/summary/usage 用中文)\n"
        f"===REPRO_REPORT_START===\n"
        f"{_WEB_REPORT_EXAMPLE}\n"
        f"===REPRO_REPORT_END===\n\n"
        f"usage 字段是给用户看的\"使用说明\", 不要写安装部署步骤, 重点写怎么用: "
        f"what=项目是干什么的; how_to_use=打开页面后怎么操作; prerequisites=必须先配好什么; limitations=有什么限制。"
        f"prerequisites 只写当前使用者仍需自行完成的前置条件——若本次复现已配置并验证了 LLM/API/数据库, "
        f"必须明确写\"当前复现环境已配置并验证 …, 无需用户额外配置\", 不能泛泛写\"需要配置 LLM API\"。"
        f"复现失败(failed)则 usage 只填 what 和 limitations。\n"
        f"安全/攻击类工具报告: 最终报告【不要原样回显攻击载荷、恶意样本或敏感内容】, 用\"攻击载荷1/2/3\"或 <redacted> 代替, "
        f"只写攻击类型、步骤与结论——避免模型内容审核中断报告, 也让报告更易读。\n"
        f"诚实第一: 项目没有 Web 界面就如实说, 绝不编造页面充数; 跑不起来就 failed 并在 blockers 说清缺什么。"
        f"JSON 之后再另起一行输出: FINAL_VERDICT: SUCCESS 或 PARTIAL 或 FAILURE。"
    )


def _send_message(base_url: str, headers: dict[str, str], session_id: str, code_url: str, title: str, timeout: int, task_id: int) -> dict[str, Any]:
    prompt = _build_repro_prompt(code_url, task_id)
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
    if isinstance(msg_data, list):
        msg_data = msg_data[-1] if msg_data else {}
    if not isinstance(msg_data, dict):
        return ""
    parts = msg_data.get("parts") or []
    return "\n".join(p.get("text", "") for p in parts if isinstance(p, dict) and p.get("type") == "text")


def _fetch_transcript_text(base_url: str, headers: dict[str, str], session_id: str) -> str:
    """agent 运行被中断时, 从 serve 拉取会话已产出的 assistant 文本(尽力而为)。"""
    try:
        req = urllib.request.Request(f"{base_url}/session/{session_id}/message", headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.loads(resp.read())
        msgs = data if isinstance(data, list) else (data.get("messages") or [])
        texts: list[str] = []
        for m in msgs:
            if not isinstance(m, dict):
                continue
            info = m.get("info") or {}
            if info.get("role") != "assistant":
                continue
            for p in m.get("parts") or []:
                if isinstance(p, dict) and p.get("type") == "text":
                    texts.append(str(p.get("text", "")))
        return "\n".join(texts)
    except Exception:  # noqa: BLE001 - 拉取失败不阻断主流程
        return ""


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


def _parse_report(full_text: str) -> tuple[dict | None, str]:
    """解析 agent 全文里的结构化 JSON 报告(复用旧 extract_report), 返回 (report, status)。
    status 优先级: JSON 报告 status > FINAL_VERDICT > 关键词兜底。"""
    report: dict | None = None
    try:
        from ai4sec_platform.domains.capabilities.adapters.repro_runner import extract_report

        report = extract_report(full_text)
    except Exception:  # noqa: BLE001 - 解析失败降级
        report = None
    status: str | None = None
    if isinstance(report, dict):
        s = report.get("status")
        if s == "succeeded":
            s = "success"
        if s in ("success", "partial", "failed"):
            status = s
    if not status:
        status = _detect_verdict(full_text)
    return report, status


def _is_machine_line(line: str) -> bool:
    """排除原始 JSON / 命令 / 代码行, 避免把结构化 step 字符串当作文本结论。"""
    s = line.strip()
    if s.startswith("{"):
        return True
    if '"cmd"' in s or '"steps"' in s or '"blockers"' in s:
        return True
    if s.startswith(("```", "$ ", "git ", "cd ", "pip ", "npm ", "python", "poetry ", "docker ")):
        return True
    return False


def _fallback_report(session_id: str, full_text: str, reason: str) -> tuple[dict[str, Any], str]:
    """中断/超时且无结构化报告时, 构造带中文结论的兜底报告。返回 (report, verdict)。
    有阶段文本→partial(有进展), 全空→failed。summary 优先取结论性句子(跳过 JSON/命令行)。"""
    lines = [l.strip() for l in full_text.splitlines() if l.strip() and not _is_machine_line(l)]
    key_line = next(
        (l for l in reversed(lines) if any(k in l for k in ("核心", "跑通", "成功", "完成", "失败", "结论", "已就绪"))),
        lines[-1] if lines else "",
    )
    verdict = "partial" if lines else "failed"
    report = {
        "status": verdict,
        "summary": key_line[:200] if key_line else f"复现{reason}, agent 未产出有效输出",
        "web_started": False,
        "web_framework": "",
        "start_command": "",
        "verify": "",
        "project_type": "auto",
        "core_workflow": {"goal": "", "mode": "real", "verified": False, "result": "", "evidence": []},
        "environment": {"provider": "opencode-serve", "session_id": session_id},
        "steps": [],
        "blockers": [reason],
        "gotchas": [],
        "usage": {"what": "项目复现未能产出最终报告", "how_to_use": "", "prerequisites": "", "limitations": f"复现{reason}, 已产出阶段文本见日志, 需人工查看会话补判"},
    }
    return report, verdict


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
                result_box["value"] = _send_message(repro_url, headers, session_id, code_url, title, timeout, task_id)
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
            if isinstance(tokens, dict) and tokens.get("input") is not None:
                line += f" · tokens in={tokens.get('input')} out={tokens.get('output') or 0}"
            _append_log(task_id, line)
            time.sleep(15)

        if "error" in result_box:
            raise result_box["error"]

        msg_data = result_box["value"]
        full_response = _extract_full_response(msg_data)
        run_error = ""
        if isinstance(msg_data, dict):
            err = msg_data.get("error")
            if isinstance(err, dict):
                run_error = str(err.get("message") or json.dumps(err, ensure_ascii=False))[:400]
            elif isinstance(err, str):
                run_error = err[:400]

        interrupted = bool(run_error) or not full_response.strip()
        if interrupted and not full_response.strip():
            _append_log(task_id, "⚠ agent 运行被中断(可能是模型内容审核或 API 错误), 尝试从会话拉取已产出文本…")
            full_response = _fetch_transcript_text(repro_url, headers, session_id)
            if full_response.strip():
                _append_log(task_id, f"已从会话拉取 {len(full_response.splitlines())} 行已产出文本")

        report, verdict = _parse_report(full_response)

        if interrupted and not report:
            # 无结构化报告且被中断: 构造带中文结论的兜底报告(有阶段文本→partial, 全空→failed)
            reason = f"复现过程中断: {run_error}" if run_error else "复现过程中断(agent 未输出最终报告)"
            report, verdict = _fallback_report(session_id, full_response, reason)
            _append_log(task_id, f"[复现完成-中断] agent 未输出最终结构化报告, 已产出阶段文本, 判定 {verdict.upper()}")
        else:
            _append_log(task_id, f"[复现完成] 判定 {verdict.upper()}，复现过程与报告:")
            if run_error:
                report = report or {}
                report.setdefault("blockers", [])
                report["blockers"].append(f"复现末尾异常: {run_error}")

        for line in full_response.splitlines():
            _append_log(task_id, line)

        # 结构化关键步骤/实际运行也落日志, 便于页面日志区直接看
        steps = (report or {}).get("steps") or []
        if steps:
            _append_log(task_id, f"— 关键步骤 {len(steps)} 条 —")
            for st in steps:
                mark = "✓" if st.get("ok") else "✗"
                note = f"  ({st.get('note')})" if st.get("note") else ""
                _append_log(task_id, f"{mark} {st.get('cmd', '')}{note}")
        summary = (report or {}).get("summary") or full_response.strip()[:400]
        report_json: dict[str, Any] = report if isinstance(report, dict) else {
            "status": verdict,
            "summary": summary,
            "level": "auto",
            "project_type": "auto",
            "environment": {"provider": "opencode-serve", "session_id": session_id},
            "steps": [],
        }
        report_json.setdefault("status", verdict)
        report_json.setdefault("summary", summary)
        report_json.setdefault("environment", {"provider": "opencode-serve", "session_id": session_id})
        report_json.setdefault("steps", [])

        # 对外访问链接: web 服务已启动时, 通过平台反代路径开放给用户点击
        web_started = bool((report or {}).get("web_started"))
        _update_task(
            task_id,
            status=verdict,
            finished_at=_utc_now(),
            result=full_response[:20000],
            report_json=json.dumps(report_json, ensure_ascii=False),
            web_url=REPRO_WEB_URL if web_started else "",
            web_port=8080 if web_started else None,
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
        timed_out = "timed out" in emsg.lower()
        if timed_out:
            emsg = f"timed out after {timeout}s (REPRO_API_URL={repro_url})"
        # 超时/异常也尝试从会话拉取已产出文本, 给中文结论(不丢阶段成果)
        salvaged = _fetch_transcript_text(repro_url, headers, session_id) if session_id else ""
        if timed_out:
            reason = f"超时(上限 {timeout}s), 已产出阶段文本见日志"
            if salvaged.strip():
                # 先尝试解析会话里可能已写完整的结构化报告(agent 可能已写完, 只是 serve 响应迟到)
                report, verdict = _parse_report(salvaged)
            else:
                report, verdict = None, "failed"
            report_complete = isinstance(report, dict) and report.get("status") in ("success", "partial", "failed")
            if report_complete:
                report = dict(report)
                report.setdefault("blockers", [])
                report["blockers"].append(f"复现通道超时({timeout}s)后从会话拉取到完整报告: {emsg}")
                task_status = verdict
            else:
                report, verdict = _fallback_report(session_id, salvaged, reason)
                report["blockers"] = [f"复现超时: {emsg}"] if salvaged.strip() else [f"复现超时: {emsg}(未产出有效文本)"]
                task_status = "timeout"
            web_started = bool((report or {}).get("web_started"))
            _update_task(
                task_id, status=task_status, finished_at=_utc_now(),
                result=(salvaged or emsg)[:20000],
                report_json=json.dumps(report, ensure_ascii=False),
                web_url=REPRO_WEB_URL if web_started else "",
                web_port=8080 if web_started else None,
            )
            _append_log(task_id, f"✗ {emsg}")
            if salvaged.strip():
                _append_log(task_id, f"⏱ 通道超时, 已从会话拉取 {len(salvaged.splitlines())} 行已产出文本:")
                for line in salvaged.splitlines():
                    _append_log(task_id, line)
            _write_payload(item_id, verdict, {
                "verdict": verdict, "error": emsg, "session_id": session_id, "summary": report.get("summary"),
            }, item_status=_STATUS_TO_ITEM.get(verdict))
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
