from __future__ import annotations

import time
from typing import Any

from ai4sec_platform.domains.vulnerabilities.model_inputs import prepare_model_input
from ai4sec_platform.models.local_rules import LocalRuleProvider
from ai4sec_platform.models.router import LLMRouter

CONTENT_EXTRACT_PROMPT = """你是网页正文抽取专家。输入包含完整漏洞情报网页内容。请提取纯正文和文章发布时间，重建为干净、可读的正文，保留原始段落结构和关键信息。
必须去除所有非正文元素，包括：导航栏、侧边栏、页脚、广告、评论区、推荐列表、面包屑、搜索框、登录框、社交媒体按钮、版权声明、脚本残留、重复导航文本等。
不要总结、不要改写、不要遗漏正文段落——输出完整正文全文。
只返回 JSON：{"body":"提取并重建的干净正文全文","published_date":"发布时间，可为空","author":"作者，可为空","content_quality":"rich|usable|thin","reason":"简短说明"}。"""

SLICE_EXTRACT_PROMPT = """你是网页正文抽取专家。输入包含完整漏洞情报网页内容。请识别真正正文边界，排除导航、页脚、广告、评论和推荐列表。
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

                # 1) 重建式正文: 干净正文, 去导航/广告/页脚
                reconstructed = _reconstruct(provider, payload)
                if reconstructed:
                    body, result, resp = reconstructed
                    return {
                        **page,
                        "cleaned_text": body,
                        "markdown_length": len(body),
                        "content_length": len(body),
                        "published_at": result.get("published_date") or page.get("published_at") or "",
                        "content_quality": result.get("content_quality") or _quality(body),
                        "content_extraction": {"provider": resp.get("provider"), "model": resp.get("model"), "model_attempted": True, "model_used": True, "status": "success", "prompt": CONTENT_EXTRACT_PROMPT, "llm_output": result, "reason": result.get("reason", ""), "model_input_characters": len(raw_content), "model_input_truncated": input_truncated, "latency_ms": int((time.perf_counter() - started) * 1000)},
                    }

                # 2) 重建式失败(超长页模型空返回/网络抖动) → 边界切片兜底: 保留正文, 不丢成原始 markdown
                sliced = _slice(provider, payload, markdown)
                if sliced:
                    body, slice_result, slice_resp = sliced
                    return {
                        **page,
                        "cleaned_text": body,
                        "markdown_length": len(body),
                        "content_length": len(body),
                        "published_at": slice_result.get("published_date") or page.get("published_at") or "",
                        "content_quality": slice_result.get("content_quality") or _quality(body),
                        "content_extraction": {"provider": slice_resp.get("provider"), "model": slice_resp.get("model"), "model_attempted": True, "model_used": True, "status": "sliced", "prompt": SLICE_EXTRACT_PROMPT, "llm_output": slice_result, "reason": "重建式未产出正文, 用边界切片保留原文: " + str(slice_result.get("reason") or ""), "model_input_characters": len(raw_content), "model_input_truncated": input_truncated, "latency_ms": int((time.perf_counter() - started) * 1000)},
                    }

                # 3) 都失败: 诚实标记, 保留原文供人工复核
                return {
                    **page,
                    "cleaned_text": markdown,
                    "markdown_length": len(markdown),
                    "content_quality": _quality(markdown),
                    "content_extraction": {"provider": provider_name or "unknown", "model_attempted": True, "model_used": False, "status": "empty_body", "reason": "重建式与边界切片均未产出正文", "model_input_characters": len(raw_content), "model_input_truncated": input_truncated, "latency_ms": int((time.perf_counter() - started) * 1000)},
                }
        except Exception as exc:  # pragma: no cover - external model dependent
            page = {**page, "content_extraction_error": str(exc)[:300]}
            return {**page, "cleaned_text": markdown, "markdown_length": len(markdown), "content_quality": _quality(markdown), "content_extraction": {"provider": provider_name or "unknown", "model_attempted": True, "model_used": False, "status": "fallback", "reason": page.get("content_extraction_error"), "latency_ms": int((time.perf_counter() - started) * 1000)}}
    return {**page, "cleaned_text": markdown, "markdown_length": len(markdown), "content_quality": _quality(markdown), "content_extraction": {"provider": "local_rules", "model_attempted": False, "model_used": False, "status": "fallback", "reason": page.get("content_extraction_error", "model unavailable or disabled"), "latency_ms": 0}}


def _reconstruct(provider: Any, payload: dict[str, Any]) -> tuple[str, dict, dict] | None:
    try:
        resp = provider.complete_json(prompt=CONTENT_EXTRACT_PROMPT, payload=payload)
    except RuntimeError:
        # 模型空返回/无效 JSON(长页放弃重建) → 试切片兜底; 网络类异常向上抛触发熔断
        return None
    result = resp.get("result") or resp.get("parsed") or {}
    body = str(result.get("body") or "").strip()
    return (body, result, resp) if body else None


def _slice(provider: Any, payload: dict[str, Any], markdown: str) -> tuple[str, dict, dict] | None:
    try:
        resp = provider.complete_json(prompt=SLICE_EXTRACT_PROMPT, payload=payload)
    except RuntimeError:
        return None
    result = resp.get("result") or resp.get("parsed") or {}
    body = _slice_by_markers(markdown, str(result.get("body_start") or ""), str(result.get("body_end") or ""))
    # 切片必须严格短于原文才算有用, 否则退化为整篇原文
    if body and body != markdown.strip() and len(body) < len(markdown):
        return (body, result, resp)
    return None


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
