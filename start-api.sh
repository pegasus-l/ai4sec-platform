#!/bin/bash
cd /app
export PYTHONPATH=/app/src

# 能力洞察：每15分钟
(
  sleep 60
  while true; do
    python3 -c 'import sys; from ai4sec_platform.pipelines.runner import PipelineRunner; r=PipelineRunner(); result=r.run("capabilities.from_news_pipeline"); print("PIPELINE:", result.get("status"))' >> /var/log/ai4sec-pipeline.log 2>&1
    sleep 900
  done
) &

# 威胁洞察：每24小时
(
  sleep 120
  while true; do
    python3 -c 'import sys; from ai4sec_platform.pipelines.runner import PipelineRunner; r=PipelineRunner(); result=r.run("threats.huawei_full_migration_pipeline"); print("PIPELINE:", result.get("status"))' >> /var/log/ai4sec-pipeline.log 2>&1
    sleep 86400
  done
) &

# 漏洞洞察：每24小时
(
  sleep 180
  while true; do
    python3 -c 'import sys; from ai4sec_platform.pipelines.runner import PipelineRunner; r=PipelineRunner(); result=r.run("vulnerabilities.full_knowledge_discovery_pipeline"); print("PIPELINE:", result.get("status"))' >> /var/log/ai4sec-pipeline.log 2>&1
    sleep 86400
  done
) &

# 前台：API 服务
exec uvicorn ai4sec_platform.app.main:app --host 0.0.0.0 --port 8100
