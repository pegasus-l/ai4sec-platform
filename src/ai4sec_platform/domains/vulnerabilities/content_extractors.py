from __future__ import annotations

from typing import Any

from ai4sec_platform.domains.vulnerabilities.model_inputs import prepare_model_input
from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.router import LLMRouter

CONTENT_EXTRACT_PROMPT = """你是网页正文抽取专家。请从漏洞情报网页抓取内容中提取真正的正文，去掉导航、页脚、广告、评论、推荐列表等噪声。
只返回 JSON：{"body":"正文", "published_date":"可为空", "author":"可为空", "content_quality":"rich|usable|thin", "reason":"简短说明"}。"""


def extract_page_content(page: dict[str, Any], *, use_model: bool = True) -> dict[str, Any]:
    markdown = str(page.get("markdown") or page.get("content") or page.get("snippet") or "")
    if not page.get("success") or not markdown.strip():
        return {**page, "cleaned_text": "", "content_extraction": {"provider": "none", "model_used": False, "status": "skipped", "reason": page.get("error") or "empty content"}}
    if use_model:
        try:
            provider = LLMRouter().provider_for("vulnerability_content_extractor")
            if not isinstance(provider, LocalRuleProvider):
                raw_content, input_truncated = prepare_model_input(markdown, profile="vulnerability_content_extractor")
                payload = {"url": page.get("url"), "title": page.get("title"), "raw_content": raw_content}
                response = provider.complete_json(prompt=CONTENT_EXTRACT_PROMPT, payload=payload)
                result = response.get("result") or response.get("parsed") or {}
                body = str(result.get("body") or "").strip()
                if body:
                    return {
                        **page,
                        "cleaned_text": body,
                        "markdown_length": len(body),
                        "content_length": len(body),
                        "published_at": result.get("published_date") or page.get("published_at") or "",
                        "content_quality": result.get("content_quality") or _quality(body),
                        "content_extraction": {"provider": response.get("provider"), "model": response.get("model"), "model_used": True, "status": "success", "prompt": CONTENT_EXTRACT_PROMPT, "llm_output": result, "reason": result.get("reason", ""), "model_input_characters": len(raw_content), "model_input_truncated": input_truncated},
                    }
        except Exception as exc:  # pragma: no cover - external model dependent
            page = {**page, "content_extraction_error": str(exc)[:300]}
    return {**page, "cleaned_text": markdown, "content_quality": _quality(markdown), "content_extraction": {"provider": "local_rules", "model_used": False, "status": "fallback", "reason": page.get("content_extraction_error", "model unavailable or disabled")}}


def _quality(text: str) -> str:
    if len(text) >= 3000:
        return "rich"
    if len(text) >= 800:
        return "usable"
    return "thin"
