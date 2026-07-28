from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone
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
    core_query_count: int = 0
    rotation_total: int = 0
    rotation_batch_size: int = 0
    rotation_offset: int = 0
    rotation_selected_count: int = 0


def list_keyword_profiles(project_root: Path, output_dir: Path | None = None) -> list[dict[str, Any]]:
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
        core_queries = [*explicit_queries, *category_queries]
        rotation = profile.get("rotation") if isinstance(profile.get("rotation"), dict) else {}
        rotation_categories = [str(value) for value in rotation.get("categories") or []]
        rotation_queries = _category_queries(str(name), rotation_categories, categories_config)
        core_keys = {query.casefold() for query in core_queries}
        rotation_queries = [query for query in rotation_queries if query.casefold() not in core_keys]
        rotation_batch_size = min(_positive_int(rotation.get("batch_size"), len(rotation_queries)), len(rotation_queries))
        configured_queries = len(core_queries) + rotation_batch_size
        state = load_keyword_rotation_state(output_dir, str(name)) if output_dir and rotation_queries else _default_rotation_state()
        result.append({
            "name": str(name),
            "description": str(profile.get("description") or ""),
            "configured_queries": configured_queries,
            "max_queries": _positive_int(profile.get("max_queries"), configured_queries),
            "categories": categories,
            "core_queries": len(core_queries),
            "rotation_batch_size": rotation_batch_size,
            "rotation_total": len(rotation_queries),
            "rotation_cursor": int(state["cursor"]) % len(rotation_queries) if rotation_queries else 0,
            "rotation_round": int(state["round"]),
            "rotation_cycle_runs": math.ceil(len(rotation_queries) / rotation_batch_size) if rotation_batch_size else 0,
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
    queries = [*explicit_queries, *_category_queries(profile_name, category_names, categories_config)]
    core_query_count = len(queries)
    rotation = profile.get("rotation") if isinstance(profile.get("rotation"), dict) else {}
    rotation_categories = [str(value) for value in rotation.get("categories") or []]
    rotation_pool = _category_queries(profile_name, rotation_categories, categories_config)
    core_keys = {query.casefold() for query in queries}
    rotation_pool = [query for query in rotation_pool if query.casefold() not in core_keys]
    rotation_batch_size = min(_positive_int(rotation.get("batch_size"), len(rotation_pool)), len(rotation_pool))
    rotation_offset = _non_negative_int(params.get("_rotation_offset"), 0)
    selected_rotation = _rotating_slice(rotation_pool, rotation_offset, rotation_batch_size)
    queries.extend(selected_rotation)

    configured_queries = len(queries)
    profile_limit = _positive_int(profile.get("max_queries"), configured_queries)
    requested_limit = _positive_int(params.get("max_queries"), profile_limit)
    safety_limit = _positive_int(params.get("max_run_queries"), DEFAULT_MAX_RUN_QUERIES)
    if params.get("allow_large_keyword_profile"):
        effective_limit = min(requested_limit, profile_limit)
    else:
        effective_limit = min(requested_limit, profile_limit, safety_limit)
    queries = queries[:effective_limit]
    rotation_selected_count = max(0, len(queries) - min(core_query_count, len(queries)))
    return ResolvedKeywordProfile(
        name=profile_name,
        queries=queries,
        categories=category_names,
        configured_queries=configured_queries,
        truncated=len(queries) < configured_queries,
        core_query_count=core_query_count,
        rotation_total=len(rotation_pool),
        rotation_batch_size=rotation_batch_size,
        rotation_offset=rotation_offset % len(rotation_pool) if rotation_pool else 0,
        rotation_selected_count=rotation_selected_count,
    )


def keyword_rotation_state_path(output_dir: Path, profile_name: str) -> Path:
    return output_dir / "checkpoints" / "vulnerabilities" / f"{profile_name}_rotation.json"


def load_keyword_rotation_state(output_dir: Path | None, profile_name: str) -> dict[str, Any]:
    if output_dir is None:
        return _default_rotation_state()
    path = keyword_rotation_state_path(output_dir, profile_name)
    if not path.exists():
        return _default_rotation_state()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return {
        **_default_rotation_state(),
        **data,
        "cursor": _non_negative_int(data.get("cursor"), 0),
        "round": _positive_int(data.get("round"), 1),
    }


def advance_keyword_rotation_state(
    output_dir: Path,
    profile_name: str,
    *,
    rotation_total: int,
    selected_count: int,
    run_id: str,
) -> dict[str, Any]:
    state = load_keyword_rotation_state(output_dir, profile_name)
    if rotation_total <= 0 or selected_count <= 0:
        return state
    absolute_cursor = int(state["cursor"]) + selected_count
    state.update({
        "cursor": absolute_cursor % rotation_total,
        "round": int(state["round"]) + absolute_cursor // rotation_total,
        "last_run_id": run_id,
        "last_completed_at": datetime.now(timezone.utc).isoformat(),
        "last_batch_start": int(state["cursor"]) % rotation_total,
        "last_batch_size": selected_count,
    })
    path = keyword_rotation_state_path(output_dir, profile_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(yaml.safe_dump(state, allow_unicode=True, sort_keys=False), encoding="utf-8")
    temporary.replace(path)
    return state


def _category_queries(profile_name: str, category_names: list[str], categories_config: dict[str, Any]) -> list[str]:
    queries: list[str] = []
    for category_name in category_names:
        category_queries = categories_config.get(category_name)
        if not isinstance(category_queries, list):
            raise ValueError(f"keyword profile '{profile_name}' references unknown category '{category_name}'")
        queries.extend(str(value).strip() for value in category_queries if str(value).strip())
    return queries


def _rotating_slice(values: list[str], offset: int, size: int) -> list[str]:
    if not values or size <= 0:
        return []
    start = offset % len(values)
    return [values[(start + index) % len(values)] for index in range(min(size, len(values)))]


def _default_rotation_state() -> dict[str, Any]:
    return {"cursor": 0, "round": 1, "last_run_id": "", "last_completed_at": "", "last_batch_start": 0, "last_batch_size": 0}


def _positive_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _non_negative_int(value: Any, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default
