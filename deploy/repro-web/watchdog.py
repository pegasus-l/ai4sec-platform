#!/usr/bin/env python3
"""repro-web 看护 + 回收: 每 10s 由 .repro-web-watchdog.sh 调一次(独立于 opencode 会话进程树)。

职责一(原行为): 按 tasks.json 逐个任务探端口, 端口无服务就用 task-{id}.sh 拉起。

职责二(2026-09-17 新增): 回收「平台已作废」的任务目录 /workspace/repo-{id}。
  新链路平台前端点「清理」只改 DB 状态(没有宿主容器/工作区可删), 复现卷里的 clone+venv、
  常驻服务进程、nginx 分发条目都不会自动消失 —— 空间只增不减(实测: 12 个状态已是 cleaned
  的任务目录仍在卷里占 16.9G, 其中一个的服务进程还活着)。这里按平台权威列表补上:
      注销分发(register.py rm) -> 杀掉目录内的进程(TERM→KILL) -> rm -rf 目录
  顺序固定为「先注销、再杀、后删」: 反过来的话本进程/下一轮看护会把刚杀掉的服务又拉起来。

平台权威: GET {REPRO_PLATFORM_URL}/api/internal/repro-gc, 请求头 X-Repro-Token: <共享令牌>
  -> {"keep": [id...], "reap": [id...]}
     keep = 绝不动(在跑 / 已复现成功 / 刚清理还在保护期)
     reap = 现在可回收(已作废且过了保护期)
     两个名单都没有的 repo-{id} 目录 = 平台不认识的残留, 只有目录够老(REAP_STALE_SECONDS)才收。
  平台不可达时【本轮什么都不做】—— 宁可漏收, 不能误删正在跑的任务。

手动排查:
  python3 watchdog.py --gc-dry-run   # 只打印每个目录会怎么处置, 不动任何东西
  python3 watchdog.py --gc           # 立即回收一轮(不做看护)
"""
from __future__ import annotations

import json
import os
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request

D = "/workspace/.repro-web"
TASKS_JSON = f"{D}/tasks.json"
REGISTER = f"{D}/register.py"
WORKSPACE = "/workspace"

PLATFORM = os.environ.get("REPRO_PLATFORM_URL", "http://ai4sec:8100")
# 共享令牌: 平台侧叫 REPRO_PASSWORD, 本容器里是 OPENCODE_SERVER_PASSWORD(两个容器 env 名字
# 不同, 值相同), 都认。
TOKEN = os.environ.get("REPRO_PASSWORD") or os.environ.get("OPENCODE_SERVER_PASSWORD") or ""

REAP_STALE_SECONDS = 900   # 平台不认识的目录: 至少 15 分钟没动过才回收(防误删手工实验目录)
TERM_WAIT = 5              # TERM 后等这么久再 KILL
PLATFORM_ERR_LOG_SECONDS = 600  # 平台不可达的告警最小间隔(秒), 防日志刷屏
# 告警节流的时间戳放文件里: 本脚本每 10s 被当成新进程拉起, 模块级全局变量不跨 tick 累积,
# 平台长时间不通会每 tick 刷一行日志。
ERR_STAMP = f"{D}/.gc-platform-err"
DIR_RE = re.compile(r"^repo-(\d+)$")


def log(msg: str) -> None:
    print(f'[{time.strftime("%Y-%m-%dT%H:%M:%S")}] {msg}', flush=True)


# ---------------------------------------------------------------------------
# 职责一: 看护(原样保留)
# ---------------------------------------------------------------------------
def probe(port: int) -> bool:
    s = socket.socket()
    s.settimeout(3)
    try:
        return s.connect_ex(("127.0.0.1", port)) == 0
    finally:
        s.close()


def ensure_services() -> None:
    try:
        with open(TASKS_JSON) as f:
            tasks = json.load(f).get("tasks", {})
    except Exception:
        return
    for tid, t in tasks.items():
        port = t.get("port")
        launch = t.get("launch")
        if not port or not launch:
            continue
        if probe(port):
            continue
        script = f"{D}/{launch}"
        if not os.path.exists(script):
            continue
        log(f"task#{tid} port {port} down, relaunch {launch}")
        subprocess.Popen(["sh", script])


# ---------------------------------------------------------------------------
# 职责二: 回收
# ---------------------------------------------------------------------------
def _should_log_platform_err() -> bool:
    now = time.time()
    try:
        if now - os.path.getmtime(ERR_STAMP) < PLATFORM_ERR_LOG_SECONDS:
            return False
    except OSError:
        pass
    try:
        with open(ERR_STAMP, "w"):
            pass
        os.utime(ERR_STAMP, (now, now))
    except OSError:
        pass
    return True


def fetch_authority() -> tuple[set[int], set[int]] | None:
    """取平台权威名单 (keep, reap); 取不到返回 None —— 调用方必须什么都不做。"""
    if not TOKEN:
        return None
    req = urllib.request.Request(
        f"{PLATFORM}/api/internal/repro-gc", headers={"X-Repro-Token": TOKEN}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
        return (
            {int(x) for x in data.get("keep", [])},
            {int(x) for x in data.get("reap", [])},
        )
    except Exception as e:  # noqa: BLE001 - 任何失败都按「不知道」处理
        if _should_log_platform_err():
            log(f"取平台权威名单失败({e}), 本轮不做回收")
        return None


def _alive(pid: int) -> bool:
    """进程是否还活着(僵尸不算)。容器里没有 ps, 读 /proc/<pid>/stat 的 state 字段。"""
    try:
        with open(f"/proc/{pid}/stat") as f:
            state = f.read().rsplit(")", 1)[1].split()[0]
        return state not in ("Z", "X")
    except OSError:
        return False


def _pids_in(path: str) -> list[int]:
    """找出 cwd 或命令行指向 path 的进程(不含自己)。

    两个信号都要查: 服务进程通常是「cwd 在 repo 目录内 + 命令行是 venv 内相对路径」
    (如 .venv/bin/uvicorn), 而 setsid 出去的子孙进程 cwd 可能已被改, 命令行里仍带绝对路径。
    """
    me = os.getpid()
    found: list[int] = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == me:
            continue
        try:
            cwd = os.readlink(f"/proc/{pid}/cwd")
        except OSError:
            cwd = ""
        if cwd == path or cwd.startswith(path + "/"):
            found.append(pid)
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                argv = f.read().split(b"\0")
        except OSError:
            continue
        for raw in argv:
            arg = raw.decode("utf-8", "replace")
            if arg == path or arg.startswith(path + "/"):
                found.append(pid)
                break
    return found


def _kill(pids: list[int]) -> None:
    live = [p for p in pids if _alive(p)]
    for pid in live:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + TERM_WAIT
    while time.time() < deadline:
        if not any(_alive(p) for p in live):
            return
        time.sleep(0.5)
    for pid in live:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def unregister(tid: int) -> None:
    """注销 nginx 分发(tasks.json 摘条目 + 重生成 tasks.conf + 热 reload)。"""
    try:
        r = subprocess.run(
            [sys.executable, REGISTER, "rm", str(tid)],
            capture_output=True, text=True, timeout=60,
        )
        out = (r.stdout + r.stderr).strip().replace("\n", " ")
        log(f"task#{tid} 注销分发: rc={r.returncode} {out[:200]}")
    except Exception as e:  # noqa: BLE001 - 注销失败不阻断回收(目录该删还是要删)
        log(f"task#{tid} 注销分发异常: {e}")


def reap(tid: int, reason: str, dry: bool = False) -> None:
    d = f"{WORKSPACE}/repo-{tid}"
    pids = _pids_in(d) if os.path.isdir(d) else []
    if dry:
        log(f"[dry] task#{tid} 处置={reason}; 目录存在={os.path.isdir(d)} 存活进程={pids}")
        return
    unregister(tid)  # 必须先注销: 否则被杀的服务会被看护逻辑原地拉起
    if pids:
        log(f"task#{tid} 回收({reason}): 杀进程 {pids}")
        _kill(pids)
    else:
        log(f"task#{tid} 回收({reason}): 目录内无存活进程")
    if os.path.isdir(d):
        subprocess.run(["rm", "-rf", d], check=False)
        log(f"task#{tid} 已删除 {d}")


def gc_sweep(dry: bool = False) -> None:
    authority = fetch_authority()
    if authority is None:
        if dry:
            log("[dry] 平台权威名单取不到, 无法列出处置方案")
        return
    keep, reap_ids = authority
    if dry:
        log(f"[dry] 平台名单: keep={sorted(keep)} reap={sorted(reap_ids)}")
    try:
        names = sorted(os.listdir(WORKSPACE))
    except OSError as e:
        log(f"列 /workspace 失败: {e}")
        return
    for name in names:
        m = DIR_RE.match(name)
        if not m:
            continue  # repo / results / .out 之类一律不碰
        tid = int(m.group(1))
        d = f"{WORKSPACE}/{name}"
        if tid in keep:
            continue
        if tid in reap_ids:
            reap(tid, "平台判定可回收", dry=dry)
            continue
        # 平台完全没有这个 id 的任务行 = 残留目录; 只有够老才收
        try:
            age = time.time() - os.path.getmtime(d)
        except OSError:
            continue
        if age >= REAP_STALE_SECONDS:
            reap(tid, f"平台无此任务, 目录已 {int(age // 60)} 分钟未动", dry=dry)
        elif dry:
            log(f"[dry] task#{tid} 平台无此任务但目录只 {int(age)}s 未动, 暂不收")


def main() -> None:
    """一个 tick: 先看护(原行为), 再回收。回收每 tick 都跑 —— 一次本地 HTTP + 一次 listdir,
    代价可忽略, 换来「前端点清理后 ≤10s 生效」。"""
    ensure_services()
    gc_sweep()


if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--gc-dry-run" in argv:
        gc_sweep(dry=True)
    elif "--gc" in argv:
        gc_sweep()
    else:
        main()
