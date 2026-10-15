"""回收浏览器/驱动类僵尸子进程与无人认领的浏览器进程树。

**2026-10-09 事故(僵尸)**:容器的 pids 名额被僵尸进程占满(实测 pids.current 顶到
pids.max≈18585,其中约 1.6 万个是僵尸),于是:
  * 威胁跑批在 collect_huawei_sources 直接 `can't start new thread` 失败
    (2026-10-07T21:00Z、2026-10-08T21:24Z 连续两晚 failed,该步只是需要一个线程);
  * 容器里连 `docker exec` 都起不来进程。

**根因**(与 `containers` 无关,是收尸责任缺失):crawl4ai 每抓一个页面都会拉起
playwright 的 node driver + chromium 一族子进程。它们会**正常退出**,但没有人 `wait()`:
Python 的 subprocess 只负责自己 spawn 的那一个 Popen,而容器的 PID 1 就是本平台
(`uvicorn ai4sec_platform.app.main:app`,无 tini/supervisor),孤儿进程全部重挂到它名下,
于是永久停留在 Z 状态。实测:**两次成功抓取就留下 8 个僵尸**(每次约 4 个,与
"正常路径也在泄漏"吻合 —— idle-timeout 的放弃路径甚至没被触发过)。

**为什么不能用 `os.waitpid(-1, WNOHANG)` 一把梭**:那会把别的活着的子进程退出码偷走 ——
本进程里还有跑的 `subprocess.run/Popen` 调用方(复现容器管理、pipeline 里 shell 出去的步骤),
对方随后 `wait()` 会抛 ChildProcessError。所以这里**只按 pid 回收、且只回收名字像浏览器/驱动的**
僵尸(见 `_BROWSER_NEEDLES`),其它子进程一概不碰。

**2026-10-15 第二类泄漏(活着的孤儿树)**:现场逮到的不是僵尸,是**一整棵还活着的浏览器树**:

    PID 92435  ppid=1  pgid=1  comm=MainThread       103MB  ← playwright 的 node driver
     └ 92448   ppid=92435  pgid=sid=92448             183MB  chrome(独立进程组+会话)
        └ 92455/92456/92478/92481/92487/92516/92561/92653     各 48~175MB
    92450/92452  ppid=1  各自独立会话                  3.4/1.4MB  chrome_crashpad

合计约 975MB 常驻。它们**状态是 S/Sl 不是 Z**,`reap_browser_zombies()` 只看 `state == "Z"`,
所以一个都收不到 —— 这就是"修了僵尸泄漏却还会十天重演一次 OOM"的原因。

三个决定性细节,决定了修法:
  1. **node driver 的 comm 叫 `MainThread`**,不匹配任何浏览器特征词 → 只看 comm 会漏掉树根,
     必须再看 `/proc/<pid>/exe`(它是 `.../playwright/driver/node`)。
  2. **平台自己就是 PID 1** → 正在抓取的活浏览器 ppid **也等于 1**,
     「ppid==1 即孤儿」在这里**不成立**。唯一能区分活树与死树的是**进程年龄**。
  3. chrome 那层 `pgid == sid == 自己的 pid`(独立进程组),而 node driver `pgid == 1`
     (与 uvicorn 同组)→ `killpg` 只能对着**自己是组头**的进程用,
     且**绝不能对 pgid==1 调 killpg**(那会把 uvicorn 一起杀掉)。

所以 `reap_browser_orphans()` 只用"**年龄 > 宽限期**"当判据:正常抓取的单页浏览器树寿命上限
= 慢站超时 45s × (max_retries+1) 次 + 退避 ≈ 140s,宽限 600s 留了 4 倍余量;
而死了的树永远不会自己消失,迟早越过宽限期被收走。

**用法**:平台自己每 60s 跑一次(`app/main.py` 的正则任务);每页抓完(`_crawl4ai_sync`)与
启动时各再跑一次。重启容器能清空存量,但只有这两个回收器能防复发。
"""
from __future__ import annotations

import glob
import os
import signal
import sys
import threading
from typing import Any

# 浏览器/驱动进程名特征(取 comm 的小写子串匹配)。comm 只保留 15 个字符,
# 所以用 "headless_shell" 匹配不到 "headless_shell" 全名也没关系 —— "chrome"/"node" 足以覆盖。
_BROWSER_NEEDLES = ("chrome", "chromium", "headless_shell", "playwright", "node")

# **杀进程**用的特征词:比上面那组窄 —— 故意不含裸 "node"。
# 本容器里没有别的 node 调用方,但"名字里有 node"不足以证明它是浏览器(将来平台自己
# 拉个 node 构建就会误杀)。playwright 的 node driver 靠 exe 路径里的 "playwright" 认出。
_BROWSER_KILL_NEEDLES = ("chrome", "chromium", "headless_shell", "crashpad", "playwright")

# exe / cmdline 里出现这些子串也算浏览器进程(node driver 的 comm 是 "MainThread")。
_EXE_MARKERS = ("playwright", "chrome", "chromium")

# 孤儿树的宽限期(秒),见模块 docstring 第 3 点。正常单页树寿命上限约 140s。
_ORPHAN_GRACE_SECONDS = 600.0

_PROC_STAT = "/proc/[0-9]*/stat"
_PROC_UPTIME = "/proc/uptime"

# 累计回收数(进程内)。采集侧用它算"本轮回收了几个" —— 峰值快照会漏掉
# "每页收一次"的回收量(收完再快照自然是 0)。
_total_lock = threading.Lock()
_total_reaped = 0
_total_orphans_killed = 0

# 逐页的 finally 会在多个抓取线程里同时进来, 用非阻塞锁保证同一时刻只有一把刀在切。
_orphan_lock = threading.Lock()


def reaped_total() -> int:
    """进程启动至今回收的浏览器僵尸总数。"""
    with _total_lock:
        return _total_reaped


def orphans_killed_total() -> int:
    """进程启动至今 SIGKILL 掉的孤儿浏览器进程总数。"""
    with _total_lock:
        return _total_orphans_killed


def _clock_ticks() -> int:
    try:
        return int(os.sysconf("SC_CLK_TCK")) or 100
    except (OSError, ValueError):
        return 100


def _page_size() -> int:
    try:
        return int(os.sysconf("SC_PAGE_SIZE")) or 4096
    except (OSError, ValueError):
        return 4096


def _read_process_table() -> dict[int, dict[str, Any]]:
    """一次扫完 /proc, 返回 {pid: {comm, state, ppid, pgrp, starttime, rss_pages}}。

    /proc/<pid>/stat 的格式是 `pid (comm) state ppid ...`,`comm` 里可能有空格和括号,
    所以按**最后一个** ')' 切开取 comm,再按空白切后面的字段。切完后:
    index 0 = state(字段 3)、1 = ppid(4)、2 = pgrp(5)、19 = starttime(22)、21 = rss(24)。
    """
    table: dict[int, dict[str, Any]] = {}
    for path in glob.glob(_PROC_STAT):
        try:
            with open(path) as handle:
                data = handle.read()
        except OSError:  # 进程在这一瞬间退出了
            continue
        try:
            head, rest = data.split("(", 1)
            comm, tail = rest.rsplit(")", 1)
            fields = tail.split()
            table[int(head.strip())] = {
                "comm": comm,
                "state": fields[0],
                "ppid": int(fields[1]),
                "pgrp": int(fields[2]),
                "starttime": int(fields[19]),
                "rss_pages": int(fields[21]),
            }
        except (IndexError, ValueError):
            continue
    return table


def _iter_zombie_children() -> list[tuple[int, str]]:
    """本进程名下、状态为 Z(僵尸)的子进程 [(pid, comm)]。"""
    me = os.getpid()
    return [
        (pid, info["comm"])
        for pid, info in _read_process_table().items()
        if info["state"] == "Z" and info["ppid"] == me
    ]


def reap_browser_zombies() -> int:
    """回收浏览器/驱动类僵尸,返回回收个数。**不碰**其它子进程(见模块 docstring)。"""
    global _total_reaped
    reaped = 0
    for pid, comm in _iter_zombie_children():
        if not any(needle in comm.lower() for needle in _BROWSER_NEEDLES):
            continue
        try:
            # 只对确认是 Z 的自己人调用;非本进程子进程会抛 ChildProcessError,忽略即可。
            if os.waitpid(pid, os.WNOHANG)[0]:
                reaped += 1
        except (ChildProcessError, OSError):
            continue
    if reaped:
        with _total_lock:
            _total_reaped += reaped
    return reaped


def _looks_like_browser(pid: int, comm: str) -> bool:
    """是不是浏览器/驱动进程。comm 认不出来时退一步看 exe(node driver 叫 MainThread)。"""
    lowered = comm.lower()
    if any(needle in lowered for needle in _BROWSER_KILL_NEEDLES):
        return True
    try:
        exe = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return False
    exe = exe.lower()
    return any(marker in exe for marker in _EXE_MARKERS)


def _uptime_seconds() -> float:
    try:
        with open(_PROC_UPTIME) as handle:
            return float(handle.read().split()[0])
    except (OSError, ValueError, IndexError):
        return 0.0


def _process_age_seconds(info: dict[str, Any], uptime: float, ticks: int) -> float:
    """进程存活秒数。starttime 是"自开机起的时钟节拍数"。"""
    return uptime - info["starttime"] / ticks


def _rooted_at_pid1(table: dict[int, dict[str, Any]], pid: int, browser: dict[int, bool]) -> bool:
    """从 pid 沿 ppid 往上走, 途中只允许出现浏览器进程, 最终挂在 PID 1 名下。

    挂着活调用方的浏览器(理论上不该有)不会被误杀 —— 注意**正在抓取的活树也满足**这个条件
    (平台自己就是 PID 1),真正区分活死的是年龄,见 `reap_browser_orphans`。
    """
    seen: set[int] = set()
    current = pid
    while current > 1 and current not in seen:
        seen.add(current)
        info = table.get(current)
        if info is None:
            return False
        parent = info["ppid"]
        if parent == 1:
            return True
        if not browser.get(parent):
            return False
        current = parent
    return False


def _process_depth(table: dict[int, dict[str, Any]], pid: int) -> int:
    seen: set[int] = set()
    depth = 0
    current = pid
    while current > 1 and current not in seen:
        seen.add(current)
        info = table.get(current)
        if info is None:
            break
        current = info["ppid"]
        depth += 1
    return depth


def reap_browser_orphans(*, grace_seconds: float = _ORPHAN_GRACE_SECONDS) -> dict[str, Any]:
    """SIGKILL 那些**活着、超过宽限期、且没人认领**的浏览器进程树。

    返回 `{"killed", "freed_kb", "pids", "grace_seconds"}`;已有另一把刀在跑时返回 `{"skipped": "busy"}`。

    **为什么按年龄而不是按"ppid==1"判孤儿**:平台自己就是 PID 1,正在抓取的活浏览器
    ppid 也等于 1(见模块 docstring 第 2 点)。宽限 600s 对正常单页树(上限约 140s)有 4 倍余量。
    **绝不 killpg 到 pgid==1**:那是 uvicorn 自己的进程组,会把平台一起杀掉。
    """
    global _total_orphans_killed
    if not _orphan_lock.acquire(blocking=False):
        return {"killed": 0, "freed_kb": 0, "pids": [], "skipped": "busy"}
    try:
        table = _read_process_table()
        uptime = _uptime_seconds()
        ticks = _clock_ticks()
        page_size = _page_size()
        me = os.getpid()
        if uptime <= 0:  # /proc/uptime 读不到就别动手: 算不出年龄, 宁可漏杀不可错杀
            return {"killed": 0, "freed_kb": 0, "pids": [], "skipped": "no_uptime"}
        browser = {pid: _looks_like_browser(pid, info["comm"]) for pid, info in table.items()}
        victims: list[int] = []
        for pid, info in table.items():
            if pid <= 1 or pid == me or not browser[pid] or info["state"] == "Z":
                continue
            if _process_age_seconds(info, uptime, ticks) < grace_seconds:
                continue
            if not _rooted_at_pid1(table, pid, browser):
                continue
            victims.append(pid)
        if not victims:
            return {"killed": 0, "freed_kb": 0, "pids": [], "grace_seconds": grace_seconds}

        # 先杀深的: 父进程先死会把子进程重挂到 PID 1, 白多一轮扫描。
        victims.sort(key=lambda item: _process_depth(table, item), reverse=True)
        killed: list[int] = []
        freed_kb = 0
        for pid in victims:
            info = table[pid]
            pgrp = info["pgrp"]
            # 只对"自己是组头"的进程组下手;pgid==1 是 uvicorn 自己的组, 碰一下平台就没了。
            if pgrp == pid and pgrp not in (1, me):
                try:
                    os.killpg(pgrp, signal.SIGKILL)
                except OSError:
                    pass
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:  # 刚好自己退了
                continue
            killed.append(pid)
            freed_kb += info["rss_pages"] * page_size // 1024
        if killed:
            with _total_lock:
                _total_orphans_killed += len(killed)
        return {
            "killed": len(killed),
            "freed_kb": freed_kb,
            "pids": killed[:20],
            "grace_seconds": grace_seconds,
        }
    finally:
        _orphan_lock.release()


def zombie_report() -> dict[str, int]:
    """当前僵尸/浏览器进程快照,用于日志与采集 metadata(出问题时能一眼看出规模)。"""
    table = _read_process_table()
    me = os.getpid()
    zombies = [info for info in table.values() if info["state"] == "Z" and info["ppid"] == me]
    live_browser = [
        (pid, info) for pid, info in table.items()
        if pid > 1 and pid != me and info["state"] != "Z" and _looks_like_browser(pid, info["comm"])
    ]
    pids_current = pids_max = 0
    for path, key in (("/sys/fs/cgroup/pids.current", "current"), ("/sys/fs/cgroup/pids.max", "max")):
        try:
            value = int(open(path).read().strip())
        except (OSError, ValueError):
            continue
        if key == "current":
            pids_current = value
        else:
            pids_max = value
    return {
        "zombies": len(zombies),
        "browser_zombies": sum(1 for info in zombies if any(n in info["comm"].lower() for n in _BROWSER_NEEDLES)),
        # 活着的浏览器进程(含正在抓的那几棵树)。跑批中这个数会随并发在 1~5 棵之间浮动;
        # 抓取停下来后它**不归零**就说明又漏了(2026-10-15 那次就是 11 个常驻不退)。
        "browser_live": len(live_browser),
        "browser_live_rss_kb": sum(info["rss_pages"] for _, info in live_browser) * _page_size() // 1024,
        "pids_current": pids_current,
        "pids_max": pids_max,
    }


def reap_and_report(*, warn_above: int = 200) -> dict[str, int]:
    """回收 + 快照。僵尸规模超过 warn_above 时往 stderr 吼一声(否则又会静默攒到顶死)。"""
    report = zombie_report()
    reaped = reap_browser_zombies()
    orphans = reap_browser_orphans()
    report["reaped"] = reaped
    # SIGKILL 后进程不会立刻从 /proc 消失(要等下一次调度), 所以快照放到最后重取。
    if reaped or orphans.get("killed"):
        report.update(zombie_report())
    report["orphans_killed"] = orphans.get("killed", 0)
    report["orphans_freed_kb"] = orphans.get("freed_kb", 0)
    if reaped or orphans.get("killed"):
        print(
            f"[zombie-reap] reaped {reaped} zombie(s), killed {orphans.get('killed', 0)} orphan browser "
            f"process(es) ({orphans.get('freed_kb', 0) // 1024}MB freed); "
            f"live browser={report['browser_live']} ({report['browser_live_rss_kb'] // 1024}MB) "
            f"pids={report['pids_current']}/{report['pids_max']}",
            file=sys.stderr,
            flush=True,
        )
    if report["zombies"] > warn_above:
        print(
            f"[zombie-reap] 警告: 本进程名下僵尸 {report['zombies']} 个(浏览器类 {report['browser_zombies']}),"
            f" pids {report['pids_current']}/{report['pids_max']} —— 可能有新的泄漏源,需排查",
            file=sys.stderr,
            flush=True,
        )
    return report
