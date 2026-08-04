#!/bin/bash
PIPELINE_NAME=$1
cd /opt/ai-security-fusion/ai4sec
set -a; . ./.env; set +a
. .venv/bin/activate
python -c "import sys; from ai4sec_platform.pipelines.runner import PipelineRunner; r=PipelineRunner(); result=r.run(sys.argv[1]); print('PIPELINE:', result.get('status'))" "$PIPELINE_NAME" 2>&1 | tee -a /tmp/ai4sec-pipeline.log
