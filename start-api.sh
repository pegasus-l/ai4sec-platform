#!/bin/bash
cd /app
export PYTHONPATH=/app/src
export AI4SEC_VULNERABILITY_CONTENT_EXTRACTOR_MAX_OUTPUT_TOKENS=16384
# 内容提取超时 600s: 长页面重建/切片需要, 默认 180s 会导致长页降级为 slice/超时
export AI4SEC_VULNERABILITY_CONTENT_EXTRACTOR_TIMEOUT_SECONDS=600

# 2026-10-14 限制 glibc arena 堆数量(默认 8×核数=32 个)。每个 arena 是独立 64MB 堆,
# 大对象跑批后留下的空位只还堆顶、整堆不还内核 → RSS 只涨不跌。见 10-13 OOM 取证。
export MALLOC_ARENA_MAX=2

exec uvicorn ai4sec_platform.app.main:app --host 0.0.0.0 --port 8100
