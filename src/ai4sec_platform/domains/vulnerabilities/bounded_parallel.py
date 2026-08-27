from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FuturesTimeoutError, as_completed
from dataclasses import dataclass
from typing import Callable, Generic, TypeVar


InputValue = TypeVar("InputValue")
OutputValue = TypeVar("OutputValue")

# 单 item 硬 deadline 默认值: 比最坏单条 drill 任务(~1230s)更宽, 同时保证 run 不会被单条卡死拖死。
DEFAULT_ITEM_TIMEOUT_SECONDS = 1800.0


@dataclass(frozen=True)
class BoundedParallelResult(Generic[OutputValue]):
    items: list[OutputValue]
    circuit_open: bool
    parallel_batches: int


def model_max_concurrency(params: dict) -> int:
    try:
        concurrency = int(params.get("model_max_concurrency", 3))
    except (TypeError, ValueError):
        concurrency = 3
    return min(max(concurrency, 1), 8)


def model_circuit_failure_threshold(params: dict, max_concurrency: int) -> int:
    try:
        threshold = int(params.get("model_circuit_failure_threshold", max_concurrency))
    except (TypeError, ValueError):
        threshold = max_concurrency
    return min(max(threshold, 1), max_concurrency)


def run_bounded_with_circuit(
    items: list[InputValue],
    *,
    worker: Callable[[InputValue], OutputValue],
    fallback_worker: Callable[[InputValue], OutputValue],
    is_failure: Callable[[OutputValue], bool],
    max_concurrency: int,
    circuit_failure_threshold: int = 1,
    item_timeout_seconds: float | None = None,
    on_timeout: Callable[[InputValue], OutputValue] | None = None,
    on_item: Callable[[OutputValue, int, int], None] | None = None,
) -> BoundedParallelResult[OutputValue]:
    """有界并行 + 熔断。

    每个 batch 受 item_timeout_seconds 硬 deadline 约束: 单个 worker 卡死/崩溃
    会被放弃并产出超时标记(默认走 fallback_worker, 或自定义 on_timeout),
    绝不阻塞整批/整 step。熔断对"卡死的调用"同样生效(is_failure 识别超时标记)。
    """
    concurrency = min(max(int(max_concurrency), 1), 8)
    failure_threshold = max(int(circuit_failure_threshold), 1)
    try:
        timeout = float(item_timeout_seconds) if item_timeout_seconds is not None else DEFAULT_ITEM_TIMEOUT_SECONDS
    except (TypeError, ValueError):
        timeout = DEFAULT_ITEM_TIMEOUT_SECONDS
    if timeout <= 0:
        timeout = DEFAULT_ITEM_TIMEOUT_SECONDS
    output: list[OutputValue] = []
    circuit_open = False
    parallel_batches = 0
    for offset in range(0, len(items), concurrency):
        batch = items[offset : offset + concurrency]
        if circuit_open:
            fallback_results = [fallback_worker(item) for item in batch]
            output.extend(fallback_results)
            if on_item:
                for result in fallback_results:
                    on_item(result, len(output), len(items))
            continue
        parallel_batches += 1
        results = _run_batch(
            batch,
            worker=worker,
            fallback_worker=fallback_worker,
            on_timeout=on_timeout,
            timeout=timeout,
            concurrency=concurrency,
        )
        output.extend(results)
        if on_item:
            completed_before_batch = len(output) - len(results)
            for index, result in enumerate(results, start=1):
                on_item(result, completed_before_batch + index, len(items))
        circuit_open = sum(1 for result in results if is_failure(result)) >= failure_threshold
    return BoundedParallelResult(items=output, circuit_open=circuit_open, parallel_batches=parallel_batches)


def _run_batch(
    batch: list[InputValue],
    *,
    worker: Callable[[InputValue], OutputValue],
    fallback_worker: Callable[[InputValue], OutputValue],
    on_timeout: Callable[[InputValue], OutputValue] | None,
    timeout: float,
    concurrency: int,
) -> list[OutputValue]:
    """跑一个 batch, 硬 deadline 内返回全部结果(顺序按原索引)。

    超时/崩溃的 item 用 on_timeout(默认 fallback_worker)产出失败标记,
    由调用方的 is_failure 识别 → 熔断对挂起调用也生效。
    """
    results: list[OutputValue | None] = [None] * len(batch)
    executor = ThreadPoolExecutor(max_workers=min(concurrency, len(batch)))
    try:
        future_by_index = {executor.submit(worker, item): i for i, item in enumerate(batch)}
        try:
            for future in as_completed(future_by_index, timeout=timeout):
                idx = future_by_index[future]
                try:
                    results[idx] = future.result()
                except Exception:  # noqa: BLE001 - 单条 worker 崩溃不炸整个 step, 转失败标记
                    results[idx] = _on_timeout_result(batch[idx], on_timeout, fallback_worker)
        except _FuturesTimeoutError:
            # as_completed 到 deadline 未完成 → 剩余项一律按超时处理(不进卡死等待)。
            # 注意 py3.10 的 concurrent.futures.TimeoutError 与内建 TimeoutError 不是同一类。
            pass
        for future, idx in future_by_index.items():
            if results[idx] is None:
                future.cancel()  # 已在跑的取消无效, 但线程会自灭(见调用方超时自限)
                results[idx] = _on_timeout_result(batch[idx], on_timeout, fallback_worker)
    finally:
        # wait=False: 不等待卡死线程。泄漏线程由网络层硬超时保证最终自灭。
        executor.shutdown(wait=False, cancel_futures=True)
    return results


def _on_timeout_result(
    item: InputValue,
    on_timeout: Callable[[InputValue], OutputValue] | None,
    fallback_worker: Callable[[InputValue], OutputValue],
) -> OutputValue:
    if on_timeout is not None:
        try:
            return on_timeout(item)
        except Exception:  # noqa: BLE001 - 标记自身失败时退 fallback, 保证不抛
            return fallback_worker(item)
    return fallback_worker(item)
