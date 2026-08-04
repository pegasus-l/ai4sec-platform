#!/bin/bash
cd /opt/ai-security-fusion/ai4sec
set -a; . ./.env; set +a
exec .venv/bin/uvicorn ai4sec_platform.app.main:app --host 127.0.0.1 --port 8100
