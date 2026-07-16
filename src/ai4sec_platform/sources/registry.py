from __future__ import annotations

from ai4sec_platform.sources.connectors import all_connectors


class SourceRegistry:
    def __init__(self) -> None:
        self._connectors = {item.connector_name: item for item in all_connectors()}

    def get(self, name: str):
        try:
            return self._connectors[name]
        except KeyError as exc:
            raise ValueError(f"Unknown source connector: {name}") from exc

    def list(self) -> list[dict[str, str]]:
        return [{"connector_name": key, "source_type": value.source_type} for key, value in sorted(self._connectors.items())]
