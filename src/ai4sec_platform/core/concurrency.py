from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def bounded_map(
    items: Iterable[T],
    func: Callable[[T], R],
    *,
    max_workers: int = 4,
    should_cancel: Callable[[], bool] | None = None,
    on_result: Callable[[R, int, int], None] | None = None,
) -> list[R]:
    values = list(items)
    if not values:
        return []
    cancelled = should_cancel or (lambda: False)
    workers = max(1, int(max_workers or 1))
    if workers == 1 or len(values) == 1:
        results: list[R] = []
        for item in values:
            if cancelled():
                break
            result = func(item)
            results.append(result)
            if on_result:
                on_result(result, len(results), len(values))
        return results
    results: list[R | None] = [None] * len(values)
    with ThreadPoolExecutor(max_workers=min(workers, len(values))) as executor:
        next_index = 0
        futures: dict[Future[R], int] = {}

        def submit_next() -> None:
            nonlocal next_index
            if next_index >= len(values) or cancelled():
                return
            index = next_index
            next_index += 1
            futures[executor.submit(func, values[index])] = index

        for _ in range(min(workers, len(values))):
            submit_next()
        completed = 0
        while futures:
            done, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in done:
                index = futures.pop(future)
                if future.cancelled():
                    continue
                result = future.result()
                results[index] = result
                completed += 1
                if on_result:
                    on_result(result, completed, len(values))
            if cancelled():
                for future in futures:
                    future.cancel()
                continue
            for _ in done:
                submit_next()
    return [result for result in results if result is not None]
