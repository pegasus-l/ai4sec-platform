#!/bin/sh
# repro-web 多服务总机看护 (v2): 由容器启动命令拉起, 独立于 opencode 会话进程树。
# 职责:
#   1. 确保 nginx 总机(常驻 8080)在跑 —— 容器重启后 nginx 不会自动起, 这里负责拉起。
#   2. 每 10s 按 tasks.json 逐个任务看护: 任务端口无服务就用 task-{id}.sh 拉起。
# 旧版 current.sh/8080 单服务机制已废弃(8080 现在属于 nginx 总机, 任务端口为 8101~8199 自选)。
LOG=/workspace/.repro-web/watchdog.log
D=/workspace/.repro-web
NGX_CONF=$D/nginx/nginx.conf
PID_FILE=$D/nginx/nginx.pid
mkdir -p "$D/nginx"

ts() { date +%FT%T; }

probe_8080() {
  python3 -c "import socket,sys; s=socket.socket(); s.settimeout(3); sys.exit(0 if s.connect_ex(('127.0.0.1',8080))==0 else 1)" 2>/dev/null
}

ensure_nginx() {
  # 若 nginx.pid 存在且进程活着则跳过; 否则配置校验后拉起。
  if [ -f "$PID_FILE" ]; then
    if kill -0 "$(cat "$PID_FILE" 2>/dev/null)" 2>/dev/null; then
      return 0
    fi
  fi
  echo "[$(ts)] nginx not running, starting" >> "$LOG"
  if nginx -t -c "$NGX_CONF" >> "$LOG" 2>&1; then
    nginx -c "$NGX_CONF"
    echo "[$(ts)] nginx started (master pid $(cat "$PID_FILE" 2>/dev/null))" >> "$LOG"
  else
    echo "[$(ts)] nginx -t FAILED, skip start" >> "$LOG"
  fi
}

while true; do
  ensure_nginx
  python3 "$D/watchdog.py" >> "$LOG" 2>&1
  sleep 10
done
