from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.threats.attack_surface_scoring import filter_project


def filter_threat_project(project: dict[str, Any]) -> dict[str, Any]:
    return filter_project(str(project.get("name") or ""), str(project.get("description") or project.get("summary") or ""), int(project.get("star_count") or project.get("stars") or 0))
