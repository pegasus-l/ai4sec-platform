#!/bin/bash
# 给 repo-15 建 volume 内持久 venv, 装 webui 启动所需(≈pyproject runtime 全量)依赖, 验证 import。
# 幂等: venv 已存在则复用, 缺 torch 才补装。由 task-15.sh 首次引导时调用。
set -e
V=/workspace/repo-15/.venv
[ -x "$V/bin/python" ] || python3 -m venv "$V"
"$V/bin/pip" install --quiet --upgrade pip
# torch 用 CPU index, 避免默认拉 2.4GB CUDA wheel
if ! "$V/bin/python" -c "import torch" 2>/dev/null; then
  echo "[boot] installing torch 2.2.2+cpu (pytorch cpu index)"
  "$V/bin/pip" install --quiet --no-cache-dir torch==2.2.2+cpu --index-url https://download.pytorch.org/whl/cpu
fi
echo "[boot] installing webui deps (streamlit + pyproject runtime)"
"$V/bin/pip" install --quiet --no-cache-dir \
  streamlit python-dotenv pydantic aiofiles aiohttp tqdm tabulate \
  motor tornado==6.4.2 boto3 openai httpx==0.27.2 backoff art jsonpath-ng \
  numpy==1.26.4 pandas==2.2.2 transformers==4.51.3 \
  sentence-transformers fschat pygad
echo "[boot] verifying import fuzzyai.webui"
cd /workspace/repo-15/src
"$V/bin/python" -c "import sys; sys.path.insert(0,'.'); import fuzzyai.webui; print('IMPORT OK')"
echo "[boot] DONE"
