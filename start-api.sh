#!/bin/bash
cd /app
export PYTHONPATH=/app/src
# 启动 cron 守护进程(承载 */15 数据拉取调度)
service cron start
export AI4SEC_VULNERABILITY_CONTENT_EXTRACTOR_MAX_OUTPUT_TOKENS=16384
# 内容提取超时 600s: 长页面重建/切片需要, 默认 180s 会导致长页降级为 slice/超时
export AI4SEC_VULNERABILITY_CONTENT_EXTRACTOR_TIMEOUT_SECONDS=600

exec uvicorn ai4sec_platform.app.main:app --host 0.0.0.0 --port 8100
