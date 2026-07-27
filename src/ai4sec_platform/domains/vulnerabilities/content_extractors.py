from __future__ import annotations

import time
from typing import Any

from ai4sec_platform.domains.vulnerabilities.model_inputs import prepare_model_input
from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.router import LLMRouter

CONTENT_EXTRACT_PROMPT = """你是网页正文抽取专家。输入包含完整漏洞情报网页内容。请识别真正正文边界，排除导航、页脚、广告、评论和推荐列表。
不要复制或改写整篇正文，只返回用于定位正文的短边界文本和元数据。
只返回 JSON：{"body_start":"正文开头连续短句，可为空", "body_end":"正文结尾连续短句，可为空", "published_date":"可为空", "author":"可为空", "content_quality":"rich|usable|thin", "reason":"简短说明"}。"""


def extract_page_content(page: dict[str, Any], *, use_model: bool = True) -> dict[str, Any]:
    markdown = str(page.get("markdown") or page.get("content") or page.get("snippet") or "")
    if not page.get("success") or not markdown.strip():
        return {**page, "cleaned_text": "", "content_extraction": {"provider": "none", "model_used": False, "status": "skipped", "reason": page.get("error") or "empty content"}}
    if use_model:
        started = time.perf_counter()
        provider_name = ""
        try:
            provider = LLMRouter().provider_for("vulnerability_content_extractor")
            if not isinstance(provider, LocalRuleProvider):
                provider_name = str(getattr(provider, "provider_name", ""))
                raw_content, input_truncated = prepare_model_input(markdown, profile="vulnerability_content_extractor")
                payload = {"url": page.get("url"), "title": page.get("title"), "raw_content": raw_content}
                response = provider.complete_json(prompt=CONTENT_EXTRACT_PROMPT, payload=payload)
                result = response.get("result") or response.get("parsed") or {}
                body = str(result.get("body") or "").strip() or _slice_by_markers(markdown, str(result.get("body_start") or ""), str(result.get("body_end") or ""))
                if body:
                    return {
                        **page,
                        "cleaned_text": body,
                        "markdown_length": len(body),
                        "content_length": len(body),
                        "published_at": result.get("published_date") or page.get("published_at") or "",
                        "content_quality": result.get("content_quality") or _quality(body),
                        "content_extraction": {"provider": response.get("provider"), "model": response.get("model"), "model_attempted": True, "model_used": True, "status": "success", "prompt": CONTENT_EXTRACT_PROMPT, "llm_output": result, "reason": result.get("reason", ""), "model_input_characters": len(raw_content), "model_input_truncated": input_truncated, "latency_ms": int((time.perf_counter() - started) * 1000)},
                    }
        except Exception as exc:  # pragma: no cover - external model dependent
            page = {**page, "content_extraction_error": str(exc)[:300]}
            return {**page, "cleaned_text": markdown, "content_quality": _quality(markdown), "content_extraction": {"provider": provider_name or "unknown", "model_attempted": True, "model_used": False, "status": "fallback", "reason": page.get("content_extraction_error"), "latency_ms": int((time.perf_counter() - started) * 1000)}}
    return {**page, "cleaned_text": markdown, "content_quality": _quality(markdown), "content_extraction": {"provider": "local_rules", "model_attempted": False, "model_used": False, "status": "fallback", "reason": page.get("content_extraction_error", "model unavailable or disabled"), "latency_ms": 0}}


def _slice_by_markers(markdown: str, start_marker: str, end_marker: str) -> str:
    start = markdown.find(start_marker.strip()) if start_marker.strip() else -1
    end = markdown.rfind(end_marker.strip()) if end_marker.strip() else -1
    if start >= 0 and end >= start:
        return markdown[start:end + len(end_marker.strip())].strip()
    if start >= 0:
        return markdown[start:].strip()
    if end >= 0:
        return markdown[:end + len(end_marker.strip())].strip()
    return markdown


def _quality(text: str) -> str:
    if len(text) >= 3000:
        return "rich"
    if len(text) >= 800:
        return "usable"
    return "thin"
