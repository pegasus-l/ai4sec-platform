from __future__ import annotations

import hashlib
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from ai4sec_platform.domains.news.schemas import NormalizedNewsItem


def normalize_raw_item(source: str, item: dict[str, Any]) -> dict[str, Any] | None:
    if source == "arxiv":
        normalized = _normalize_arxiv(source, item)
    elif source == "github":
        normalized = _normalize_github(source, item)
    elif source == "rss":
        normalized = _normalize_reference(source, item)
    else:
        normalized = _normalize_reference(source, item)
    if normalized.get("source_type") not in {"paper", "project"}:
        return None
    return NormalizedNewsItem.model_validate(normalized).model_dump()


def _normalize_arxiv(source: str, item: dict[str, Any]) -> dict[str, Any]:
    raw_id = str(item.get("id") or item.get("arxiv_id") or item.get("url") or "")
    arxiv_id = _arxiv_id(raw_id)
    url = _canonical_url(item.get("url") or item.get("paper_url") or (f"https://arxiv.org/abs/{arxiv_id}" if arxiv_id else ""))
    authors = [_author_name(author) for author in item.get("authors") or []]
    categories = item.get("categories") or item.get("topics") or []
    return {
        "item_key": f"paper:arxiv:{arxiv_id}" if arxiv_id else _fallback_key(source, item),
        "source": source,
        "source_type": "paper",
        "title": _clean_text(item.get("title")) or "未命名论文",
        "url": url,
        "paper_url": url,
        "primary_date": item.get("published") or item.get("published_at") or item.get("updated") or "",
        "updated_at": item.get("updated") or "",
        "summary": _clean_text(item.get("summary") or item.get("abstract")),
        "authors": [author for author in authors if author],
        "topics": _string_list(categories),
        "code_url": item.get("code_url") or item.get("code") or next(iter(item.get("code_urls") or item.get("github_repos") or []), ""),
        "related_project_names": [_github_full_name(value) for value in item.get("code_urls") or item.get("github_repos") or [] if _github_full_name(value)],
        "external_id": arxiv_id,
        "discovered_from": [source],
        "raw": item,
    }


def _normalize_github(source: str, item: dict[str, Any]) -> dict[str, Any]:
    url = _canonical_url(item.get("html_url") or item.get("url") or item.get("repo_url") or "")
    full_name = str(item.get("full_name") or _github_full_name(url))
    owner = item.get("owner") or {}
    owner_name = owner.get("login") if isinstance(owner, dict) else str(owner)
    topics = item.get("topics") or []
    return {
        "item_key": f"project:github:{full_name.lower()}" if full_name else _fallback_key(source, item),
        "source": source,
        "source_type": "project",
        "title": item.get("full_name") or item.get("name") or full_name or "未命名项目",
        "url": url,
        "primary_date": item.get("updated_at") or item.get("pushed_at") or item.get("created_at") or "",
        "updated_at": item.get("updated_at") or item.get("pushed_at") or "",
        "summary": _clean_text(item.get("description") or item.get("summary")),
        "authors": [owner_name] if owner_name else [],
        "topics": _string_list(topics),
        "code_url": url,
        "repo_full_name": full_name,
        "external_id": str(item.get("id") or full_name),
        "stars": _int(item.get("stargazers_count") or item.get("stars")),
        "forks": _int(item.get("forks_count") or item.get("forks")),
        "language": str(item.get("language") or ""),
        "related_paper_ids": [value for value in (_arxiv_id(str(item_id)) for item_id in item.get("arxiv_ids") or []) if value],
        "discovered_from": [source],
        "raw": item,
    }


def _normalize_rss(source: str, item: dict[str, Any]) -> dict[str, Any]:
    url = _canonical_url(item.get("link") or item.get("url") or item.get("source_url") or "")
    return {
        "item_key": f"url:{url}" if url else _fallback_key(source, item),
        "source": source,
        "source_type": "article",
        "title": _clean_text(item.get("title")) or "未命名资讯",
        "url": url,
        "primary_date": item.get("published") or item.get("published_at") or item.get("pubDate") or item.get("updated") or "",
        "updated_at": item.get("updated") or "",
        "summary": _clean_text(item.get("summary") or item.get("description") or item.get("content")),
        "authors": _string_list(item.get("authors") or ([item.get("author")] if item.get("author") else [])),
        "topics": _string_list(item.get("categories") or item.get("topics") or []),
        "discovered_from": [source],
        "raw": item,
    }


def _normalize_reference(source: str, item: dict[str, Any]) -> dict[str, Any]:
    url = _canonical_url(item.get("url") or item.get("paper_url") or item.get("repo_url") or item.get("source_url") or "")
    code_url = _canonical_url(item.get("code_url") or item.get("repo_url") or "")
    arxiv_id = _arxiv_id(url)
    repo_name = _github_full_name(code_url or url)
    source_type = "project" if repo_name else "paper" if arxiv_id or item.get("paper_url") else str(item.get("source_type") or "article")
    if source_type == "repo":
        source_type = "project"
    if source_type not in {"paper", "project"}:
        source_type = ""
    if arxiv_id:
        key = f"paper:arxiv:{arxiv_id}"
    elif repo_name:
        key = f"project:github:{repo_name.lower()}"
    elif url:
        key = f"url:{url}"
    else:
        key = _fallback_key(source, item)
    return {
        "item_key": key,
        "source": source,
        "source_type": source_type,
        "title": _clean_text(item.get("title") or item.get("name") or item.get("source_title")) or "未命名条目",
        "url": url,
        "primary_date": item.get("published") or item.get("published_at") or item.get("updated_at") or item.get("created_at") or item.get("source_date") or "",
        "updated_at": item.get("updated_at") or "",
        "summary": _clean_text(item.get("summary") or item.get("abstract") or item.get("description") or item.get("reason")),
        "authors": _string_list(item.get("authors") or []),
        "topics": _string_list(item.get("topics") or item.get("categories") or []),
        "code_url": code_url or (url if source_type == "project" else ""),
        "paper_url": url if source_type == "paper" else _canonical_url(item.get("paper_url") or ""),
        "external_id": arxiv_id or str(item.get("id") or ""),
        "repo_full_name": repo_name,
        "stars": _int(item.get("stars") or item.get("stargazers_count")),
        "forks": _int(item.get("forks") or item.get("forks_count")),
        "language": str(item.get("language") or ""),
        "discovered_from": [source],
        "raw": item,
    }


def _canonical_url(value: Any) -> str:
    url = str(value or "").strip()
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return url.rstrip("/")
    query = urlencode([(key, val) for key, val in parse_qsl(parsed.query, keep_blank_values=True) if not key.lower().startswith("utm_")])
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path.rstrip("/"), "", query, ""))


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
    return f"{parts[0]}/{parts[1].removesuffix('.git')}" if len(parts) >= 2 else ""


def _fallback_key(source: str, item: dict[str, Any]) -> str:
    raw = repr(sorted((str(key), str(value)) for key, value in item.items() if key in {"id", "title", "url", "name"}))
    return f"fallback:{source}:{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def _clean_text(value: Any) -> str:
    return " ".join(str(value or "").split())


def _author_name(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("name") or value.get("login") or "")
    return str(value or "")


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if not isinstance(value, list):
        return []
    return [text for text in (_author_name(item).strip() for item in value) if text]


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
