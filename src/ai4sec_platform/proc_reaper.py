"""回收浏览器/驱动类僵尸子进程(2026-10-09 实测出的容器 pids 耗尽根因)。

**现象**:容器的 pids 名额被僵尸进程占满(实测 pids.current 顶到 pids.max≈18585,其中约
1.6 万个是僵尸),于是:
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

**用法**:平台自己每 60s 跑一次(`app/main.py` 的正则任务);采集结束时再立刻跑一次拿即时反馈。
重启容器能清空存量,但只有这个回收器能防复发。
"""
from __future__ import annotations

import glob
import os
import sys
import threading

# 浏览器/驱动进程名特征(取 comm 的小写子串匹配)。comm 只保留 15 个字符,
# 所以用 "headless_shell" 匹配不到 "headless_shell" 全名也没关系 —— "chrome"/"node" 足以覆盖。
_BROWSER_NEEDLES = ("chrome", "chromium", "headless_shell", "playwright", "node")

_PROC_STAT = "/proc/[0-9]*/stat"

# 累计回收数(进程内)。采集侧用它算"本轮回收了几个" —— 峰值快照会漏掉
# "每页收一次"的回收量(收完再快照自然是 0)。
_total_lock = threading.Lock()
_total_reaped = 0


def reaped_total() -> int:
    """进程启动至今回收的浏览器僵尸总数。"""
    with _total_lock:
        return _total_reaped


def _iter_zombie_children() -> list[tuple[int, str]]:
    """本进程名下、状态为 Z(僵尸)的子进程 [(pid, comm)]。

    /proc/<pid>/stat 的格式是 `pid (comm) state ppid ...`,`comm` 里可能有空格和括号,
    所以按**最后一个** ')' 切开取 comm,再按空白切后面的字段。
    """
    me = os.getpid()
    out: list[tuple[int, str]] = []
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
            state, ppid = fields[0], int(fields[1])
        except (IndexError, ValueError):
            continue
        if state == "Z" and ppid == me:
            try:
                out.append((int(head.strip()), comm))
            except ValueError:
                continue
    return out


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


def zombie_report() -> dict[str, int]:
    """当前僵尸/浏览器进程快照,用于日志与采集 metadata(出问题时能一眼看出规模)。"""
    zombies = _iter_zombie_children()
    browser_zombies = sum(1 for _, comm in zombies if any(n in comm.lower() for n in _BROWSER_NEEDLES))
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
        "browser_zombies": browser_zombies,
        "pids_current": pids_current,
        "pids_max": pids_max,
    }


def reap_and_report(*, warn_above: int = 200) -> dict[str, int]:
    """回收 + 快照。僵尸规模超过 warn_above 时往 stderr 吼一声(否则又会静默攒到顶死)。"""
    report = zombie_report()
    reaped = reap_browser_zombies()
    report["reaped"] = reaped
    if reaped:
        report.update(zombie_report())
    if report["zombies"] > warn_above:
        print(
            f"[zombie-reap] 警告: 本进程名下僵尸 {report['zombies']} 个(浏览器类 {report['browser_zombies']}),"
            f" pids {report['pids_current']}/{report['pids_max']} —— 可能有新的泄漏源,需排查",
            file=sys.stderr,
            flush=True,
        )
    return report
