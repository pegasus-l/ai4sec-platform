from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import urlparse


def normalize_raw_item(source: str, item: dict[str, Any]) -> dict[str, Any]:
    if source == "arxiv":
        return _normalize_arxiv(source, item)
    if source == "github":
        return _normalize_github(source, item)
    return _normalize_reference(source, item)


def _normalize_arxiv(source: str, item: dict[str, Any]) -> dict[str, Any]:
    arxiv_id = str(item.get("id") or item.get("arxiv_id") or _arxiv_id(item.get("url") or ""))
    url = item.get("url") or (f"https://arxiv.org/abs/{arxiv_id}" if arxiv_id else "")
    return {
        "item_key": f"paper:arxiv:{arxiv_id}" if arxiv_id else _fallback_key(source, item),
        "source": source,
        "source_type": "paper",
        "title": item.get("title") or "未命名论文",
        "url": url,
        "primary_date": item.get("published") or item.get("published_at") or item.get("updated") or "",
        "summary": item.get("summary") or item.get("abstract") or "",
        "authors": item.get("authors") or [],
        "code_url": item.get("code_url") or item.get("code") or "",
        "raw": item,
    }


def _normalize_github(source: str, item: dict[str, Any]) -> dict[str, Any]:
    url = item.get("html_url") or item.get("url") or item.get("repo_url") or ""
    full_name = item.get("full_name") or _github_full_name(url)
    return {
        "item_key": f"repo:github:{full_name.lower()}" if full_name else _fallback_key(source, item),
        "source": source,
        "source_type": "repo",
        "title": item.get("full_name") or item.get("name") or full_name or "未命名仓库",
        "url": url,
        "primary_date": item.get("created_at") or item.get("updated_at") or "",
        "summary": item.get("description") or item.get("summary") or "",
        "authors": [item.get("owner", {}).get("login")] if isinstance(item.get("owner"), dict) and item.get("owner", {}).get("login") else [],
        "code_url": url,
        "stars": item.get("stargazers_count") or item.get("stars"),
        "language": item.get("language") or "",
        "raw": item,
    }


def _normalize_reference(source: str, item: dict[str, Any]) -> dict[str, Any]:
    url = item.get("url") or item.get("paper_url") or item.get("repo_url") or item.get("source_url") or ""
    source_type = "repo" if _github_full_name(url) or item.get("repo_url") else "paper" if _arxiv_id(url) or item.get("paper_url") else "article"
    code_url = item.get("code_url") or item.get("repo_url") or (url if source_type == "repo" else "")
    arxiv_id = _arxiv_id(url)
    repo_name = _github_full_name(code_url or url)
    if arxiv_id:
        key = f"paper:arxiv:{arxiv_id}"
    elif repo_name:
        key = f"repo:github:{repo_name.lower()}"
    elif url:
        key = f"url:{url.rstrip('/')}"
    else:
        key = _fallback_key(source, item)
    return {
        "item_key": key,
        "source": source,
        "source_type": source_type,
        "title": item.get("title") or item.get("name") or item.get("source_title") or "未命名条目",
        "url": url,
        "primary_date": item.get("published") or item.get("created_at") or item.get("source_date") or "",
        "summary": item.get("summary") or item.get("abstract") or item.get("description") or item.get("reason") or "",
        "authors": item.get("authors") or [],
        "code_url": code_url,
        "raw": item,
    }


def _arxiv_id(value: str) -> str:
    match = re.search(r"(?:arxiv.org/(?:abs|pdf)/)?(\d{4}\.\d{4,5})(?:v\d+)?", value or "")
    return match.group(1) if match else ""


def _github_full_name(value: str) -> str:
    if not value:
        return ""
    parsed = urlparse(value)
    if "github.com" not in parsed.netloc.lower():
        return ""
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) < 2:
        return ""
    return f"{parts[0]}/{parts[1].removesuffix('.git')}"


def _fallback_key(source: str, item: dict[str, Any]) -> str:
    raw = repr(sorted((str(k), str(v)) for k, v in item.items() if k in {"id", "title", "url", "name"}))
    return f"fallback:{source}:{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"
