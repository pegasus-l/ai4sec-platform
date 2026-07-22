from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from ai4sec_platform.core.config import load_settings
from ai4sec_platform.models.router import LLMRouter

SUMMARY_PROMPT = """
你是 AI4SEC 威胁洞察平台的代码仓摘要助手。
请只基于输入里的仓库名、原始 description、语言/标签和 CVE 统计，生成中文展示摘要。
要求：
1. 输出 JSON：{"summary_zh":"...", "confidence":0.0-1.0, "notes":"..."}。
2. 不得编造仓库不存在的能力、业务背景或修复状态。
3. 如果 description 为空，只能基于仓库名和安全统计生成保守摘要。
4. 中文摘要控制在 60 字以内。
""".strip()


def enrich_repo_summary(payload: dict[str, Any], *, enabled: bool = True, cache_dir: Path | None = None) -> dict[str, Any]:
    repo_key = str(payload.get("item_key") or payload.get("title") or "repo")
    display_name = str(payload.get("title") or repo_key.removeprefix("repo:") or repo_key)
    original = _clean(payload.get("description_original") or payload.get("summary_original") or "")
    security_summary = _clean(payload.get("security_summary") or "")
    fallback = original or security_summary or "来自威胁 raw pipeline，待风险研判。"
    if original and _contains_cjk(original):
        return {"summary_zh": original, "summary_source": "repo_description", "translation_status": "source_is_chinese", "confidence": 1.0}
    if not original:
        return {"summary_zh": fallback, "summary_source": "security_summary" if security_summary else "fallback", "translation_status": "fallback_no_description", "confidence": 0.7 if security_summary else 0.4}
    if not enabled:
        return {"summary_zh": fallback, "summary_source": "repo_description", "translation_status": "model_disabled", "confidence": 0.5}

    request_payload = _summary_payload(payload, repo_key=repo_key, display_name=display_name, original=original, security_summary=security_summary)
    cache_path = _cache_path(cache_dir, request_payload)
    cached = _read_cache(cache_path)
    if cached:
        return {**cached, "cache_hit": True}

    try:
        result = LLMRouter().complete_json(prompt=SUMMARY_PROMPT, payload=request_payload)
        parsed = result.get("result") if isinstance(result.get("result"), dict) else result.get("parsed") or {}
        summary_zh = _clean(parsed.get("summary_zh") or parsed.get("summary") or "")
        if not summary_zh:
            summary_zh = _local_summary(display_name, original)
        provider = str(result.get("provider") or "unknown")
        enriched = {
            "summary_zh": summary_zh[:180],
            "summary_source": "local_rule_summary" if provider == "local_rules" else "model_translation",
            "translation_status": "local_rules" if provider == "local_rules" else "success",
            "confidence": _safe_float(parsed.get("confidence"), 0.75),
            "model_provider": provider,
            "model_output": result,
        }
    except Exception as exc:  # pragma: no cover - defensive fallback for optional model providers
        enriched = {
            "summary_zh": _local_summary(display_name, original),
            "summary_source": "repo_description",
            "translation_status": "model_error",
            "confidence": 0.45,
            "error_message": str(exc),
        }
    _write_cache(cache_path, {key: value for key, value in enriched.items() if key != "model_output"})
    return enriched


def _summary_payload(payload: dict[str, Any], *, repo_key: str, display_name: str, original: str, security_summary: str) -> dict[str, Any]:
    raw = payload.get("raw") if isinstance(payload.get("raw"), dict) else {}
    return {
        "domain": "repo_summary",
        "item_type": "repo_summary",
        "repo_key": repo_key,
        "title": display_name,
        "description_original": original,
        "language": payload.get("language") or raw.get("language") or "",
        "topics": payload.get("topics") or raw.get("topics") or [],
        "security_summary": security_summary,
        "cve_count": payload.get("cve_count") or 0,
        "sa_count": payload.get("sa_count") or 0,
        "broad_sec_count": payload.get("broad_sec_count") or 0,
    }


def _cache_path(cache_dir: Path | None, payload: dict[str, Any]) -> Path:
    base = cache_dir or _default_cache_dir()
    signature = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    digest = hashlib.sha256(signature.encode("utf-8")).hexdigest()[:20]
    return base / f"{digest}.json"


def _default_cache_dir() -> Path:
    raw = os.getenv("AI4SEC_REPO_SUMMARY_CACHE_DIR", "")
    if raw:
        return Path(raw)
    return load_settings().output_dir / "cache" / "threats" / "repo_summaries"


def _read_cache(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _write_cache(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")


def _local_summary(repo_key: str, description: str) -> str:
    label = repo_key.removeprefix("repo:")
    if description:
        return f"{label} 代码仓：{description}"[:120]
    return f"{label} 代码仓，待补充仓库描述。"


def _contains_cjk(value: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", value or ""))


def _clean(value: Any) -> str:
    return " ".join(str(value or "").split())


def _safe_float(value: Any, fallback: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return fallback
