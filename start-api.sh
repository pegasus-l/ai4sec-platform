#!/bin/bash
cd /app
export PYTHONPATH=/app/src
# 启动 cron 守护进程(承载 */15 数据拉取调度)
service cron start
exec uvicorn ai4sec_platform.app.main:app --host 0.0.0.0 --port 8100
