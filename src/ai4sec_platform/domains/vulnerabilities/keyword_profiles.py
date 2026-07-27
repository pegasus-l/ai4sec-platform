from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


DEFAULT_MAX_RUN_QUERIES = 50


@dataclass(frozen=True)
class ResolvedKeywordProfile:
    name: str
    queries: list[str]
    categories: list[str]
    configured_queries: int
    truncated: bool


def list_keyword_profiles(project_root: Path) -> list[dict[str, Any]]:
    config_path = project_root / "configs" / "vulnerability_keywords.yaml"
    if not config_path.exists():
        raise ValueError(f"keyword profile config not found: {config_path}")
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    categories_config = config.get("categories") or {}
    profiles = config.get("profiles") or {}
    result: list[dict[str, Any]] = []
    for name, profile in profiles.items():
        if not isinstance(profile, dict):
            continue
        explicit_queries = [str(value).strip() for value in profile.get("queries") or [] if str(value).strip()]
        categories = [str(value) for value in profile.get("categories") or []]
        category_queries = [str(value).strip() for category in categories for value in categories_config.get(category, []) if str(value).strip()]
        configured_queries = len(_dedupe([*explicit_queries, *category_queries]))
        result.append({
            "name": str(name),
            "description": str(profile.get("description") or ""),
            "configured_queries": configured_queries,
            "max_queries": _positive_int(profile.get("max_queries"), configured_queries),
            "categories": categories,
        })
    return result


def resolve_keyword_profile(params: dict[str, Any], project_root: Path) -> ResolvedKeywordProfile | None:
    profile_name = str(params.get("keyword_profile") or "").strip()
    if not profile_name:
        return None

    config_path = project_root / "configs" / "vulnerability_keywords.yaml"
    if not config_path.exists():
        raise ValueError(f"keyword profile config not found: {config_path}")
    config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    profiles = config.get("profiles") or {}
    profile = profiles.get(profile_name)
    if not isinstance(profile, dict):
        available = ", ".join(sorted(str(name) for name in profiles))
        raise ValueError(f"unknown keyword_profile '{profile_name}'; available: {available}")

    categories_config = config.get("categories") or {}
    category_names = [str(name) for name in profile.get("categories") or []]
    explicit_queries = [str(value).strip() for value in profile.get("queries") or [] if str(value).strip()]
    queries = list(explicit_queries)
    for category_name in category_names:
        category_queries = categories_config.get(category_name)
        if not isinstance(category_queries, list):
            raise ValueError(f"keyword profile '{profile_name}' references unknown category '{category_name}'")
        queries.extend(str(value).strip() for value in category_queries if str(value).strip())

    queries = _dedupe(queries)
    configured_queries = len(queries)
    profile_limit = _positive_int(profile.get("max_queries"), configured_queries)
    requested_limit = _positive_int(params.get("max_queries"), profile_limit)
    safety_limit = _positive_int(params.get("max_run_queries"), DEFAULT_MAX_RUN_QUERIES)
    if params.get("allow_large_keyword_profile"):
        effective_limit = min(requested_limit, profile_limit)
    else:
        effective_limit = min(requested_limit, profile_limit, safety_limit)
    queries = queries[:effective_limit]
    return ResolvedKeywordProfile(
        name=profile_name,
        queries=queries,
        categories=category_names,
        configured_queries=configured_queries,
        truncated=len(queries) < configured_queries,
    )


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.casefold()
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default
