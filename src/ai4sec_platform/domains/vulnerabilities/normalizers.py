from __future__ import annotations

import hashlib


def normalize_material(item: dict) -> dict:
    url = item.get("url") or ""
    title = item.get("title") or url or "未命名漏洞素材"
    crawl_info = item.get("crawl_info") if isinstance(item.get("crawl_info"), dict) else {}
    return {
        "item_key": f"material:{url}" if url else f"material:{hashlib.sha1(repr(item).encode('utf-8')).hexdigest()[:16]}",
        "source": "vuln_report",
        "source_type": "material",
        "title": title,
        "url": url,
        "primary_date": item.get("published_at") or item.get("timestamp") or "",
        "summary": item.get("reason") or "；".join(item.get("key_findings") or []) or item.get("summary") or "",
        "confidence": item.get("confidence"),
        "is_relevant": bool(item.get("is_relevant")),
        "category": item.get("category") or ("高相关" if item.get("is_relevant") else "待复核"),
        "markdown_length": crawl_info.get("markdown_length"),
        "key_findings": item.get("key_findings") or [],
        "raw": item,
    }
