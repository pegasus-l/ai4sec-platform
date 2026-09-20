"""停掉旧机制: 旧 watchdog(sh 循环跑 repro-web-watchdog.sh) 与占用 8080 的旧 uvicorn。
新 nginx 总机接管 8080 前必须执行, 否则端口冲突。
"""
import os
import signal


def kill_if(cond, label):
    n = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        if int(pid) == 1:  # 永不碰容器 PID1 (compose 的 sh -c, cmdline 里含 watchdog 字样)
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cl = f.read().decode("utf-8", "replace").replace("\0", " ").strip()
        except Exception:
            continue
        if cond(cl):
            try:
                os.kill(int(pid), signal.SIGKILL)
                print(f"{label}: killed pid {pid}: {cl[:90]}")
                n += 1
            except Exception:
                pass
    if n == 0:
        print(f"{label}: none found")


# 旧看护: 只匹配真正的 watchdog 子进程(/bin/sh /workspace/.repro-web-watchdog.sh),
# 不含 compose 的 setsid 那一行(否则会误杀 PID1)
kill_if(
    lambda c: "repro-web-watchdog.sh" in c and "setsid " not in c,
    "legacy-watchdog",
)
kill_if(lambda c: "uvicorn" in c and " 8080" in c, "uvicorn:8080")
kill_if(lambda c: "current.sh" in c and "sh " in c and "workspace" in c, "current.sh-runner")
