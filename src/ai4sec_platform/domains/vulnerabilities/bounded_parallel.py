from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Generic, TypeVar


InputValue = TypeVar("InputValue")
OutputValue = TypeVar("OutputValue")


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
    on_item: Callable[[OutputValue, int, int], None] | None = None,
) -> BoundedParallelResult[OutputValue]:
    concurrency = min(max(int(max_concurrency), 1), 8)
    failure_threshold = max(int(circuit_failure_threshold), 1)
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
        with ThreadPoolExecutor(max_workers=min(concurrency, len(batch))) as executor:
            results = list(executor.map(worker, batch))
        output.extend(results)
        if on_item:
            completed_before_batch = len(output) - len(results)
            for index, result in enumerate(results, start=1):
                on_item(result, completed_before_batch + index, len(items))
        circuit_open = sum(1 for result in results if is_failure(result)) >= failure_threshold
    return BoundedParallelResult(items=output, circuit_open=circuit_open, parallel_batches=parallel_batches)
