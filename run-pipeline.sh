#!/bin/bash
cd /opt/ai-security-fusion/ai4sec
set -a; . ./.env; set +a
. .venv/bin/activate
python -c "from ai4sec_platform.pipelines.runner import PipelineRunner; r=PipelineRunner(); r.run('')" 2>&1 | tee -a /tmp/ai4sec-pipeline.log
