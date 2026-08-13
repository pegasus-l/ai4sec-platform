#!/bin/bash
# 从 PID 1 获取 Docker 注入的环境变量
export $(cat /proc/1/environ | tr '\0' '\n' | grep -v '^$')
cd /app
export PYTHONPATH=/app/src
exec python3 -m ai4sec_platform.pipelines.runner "$@"
