from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Agent(ABC):
    name: str = "agent"

    @abstractmethod
    def run(self, input_data: Any) -> dict[str, Any]:
        raise NotImplementedError

    def _as_dict(self, input_data: Any) -> dict[str, Any]:
        return input_data if isinstance(input_data, dict) else {"value": input_data}
