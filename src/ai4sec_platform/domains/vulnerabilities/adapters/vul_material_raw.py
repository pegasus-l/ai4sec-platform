from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def find_report_files(root: Path, limit: int = 50) -> list[Path]:
    files = [path for path in root.rglob("report_*.json") if path.is_file()]
    files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return files[:limit]


def load_vulnerability_reports(root: Path, limit: int = 20) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in find_report_files(root, limit=limit):
        raw = _read_json(path)
        results = raw.get("results", []) if isinstance(raw, dict) else []
        records.append({"source": "vuln_report", "path": str(path), "exists": True, "items": [item for item in results if isinstance(item, dict)], "raw": raw})
    return records


def _read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)
