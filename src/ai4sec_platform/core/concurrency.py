from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, TypeVar

T = TypeVar("T")
R = TypeVar("R")


def bounded_map(items: Iterable[T], func: Callable[[T], R], *, max_workers: int = 4) -> list[R]:
    values = list(items)
    if not values:
        return []
    workers = max(1, int(max_workers or 1))
    if workers == 1 or len(values) == 1:
        return [func(item) for item in values]
    results: list[R | None] = [None] * len(values)
    with ThreadPoolExecutor(max_workers=min(workers, len(values))) as executor:
        future_to_index = {executor.submit(func, item): index for index, item in enumerate(values)}
        for future in as_completed(future_to_index):
            results[future_to_index[future]] = future.result()
    return [result for result in results if result is not None]
