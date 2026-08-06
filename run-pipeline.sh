#!/bin/bash
PIPELINE_NAME=$1
KEYWORD_PROFILE=$2
cd /opt/ai-security-fusion/ai4sec
set -a; . ./.env; set +a
. .venv/bin/activate
python -c "
import sys
from ai4sec_platform.pipelines.runner import PipelineRunner
r = PipelineRunner()
params = {'crawl_max_concurrency': 3}
if len(sys.argv) > 2 and sys.argv[2]:
    params['keyword_profile'] = sys.argv[2]
result = r.run(sys.argv[1], params=params)
print('PIPELINE:', result.get('status'))
" "$PIPELINE_NAME" "$KEYWORD_PROFILE" 2>&1 | tee -a /tmp/ai4sec-pipeline.log
