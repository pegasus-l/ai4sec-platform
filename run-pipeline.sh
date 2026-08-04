#!/bin/bash
PIPELINE_NAME="$1"
cd /opt/ai-security-fusion/ai4sec
# 停 API 避免 SQLite 写锁冲突
systemctl stop ai4sec-api 2>/dev/null
pkill -f 'uvicorn.*8100' 2>/dev/null
sleep 2
# 跑 pipeline
set -a; . ./.env; set +a
. .venv/bin/activate
python -c "import sys; from ai4sec_platform.pipelines.runner import PipelineRunner; r=PipelineRunner(); r.run(sys.argv[1])" "$PIPELINE_NAME" 2>&1 | tee -a /tmp/ai4sec-pipeline.log
# 重启 API
systemd-run --unit=ai4sec-api --working-directory=/opt/ai-security-fusion/ai4sec /opt/ai-security-fusion/ai4sec/.venv/bin/uvicorn ai4sec_platform.app.main:app --host 127.0.0.1 --port 8100 2>/dev/null
