#!/bin/bash
cd /app
export PYTHONPATH=/app/src
# 启动 cron 守护进程(承载 */15 数据拉取调度)
service cron start
export AI4SEC_VULNERABILITY_CONTENT_EXTRACTOR_MAX_OUTPUT_TOKENS=16384

exec uvicorn ai4sec_platform.app.main:app --host 0.0.0.0 --port 8100
