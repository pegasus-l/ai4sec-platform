#!/bin/bash
cd /app
export PYTHONPATH=/app/src
# 启动 cron 守护进程（后台）
cron
# 启动 API 服务（前台）
exec uvicorn ai4sec_platform.app.main:app --host 0.0.0.0 --port 8100
