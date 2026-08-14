#!/bin/bash
cd /app
export PYTHONPATH=/app/src
exec uvicorn ai4sec_platform.app.main:app --host 0.0.0.0 --port 8100
