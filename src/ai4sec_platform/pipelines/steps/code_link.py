"""代码链接发现 + 去重——纯正则，不调LLM。"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit, parse_qsl, urlencode

GITHUB_RE = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)", re.IGNORECASE)
TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "fbclid", "gclid"}


def discover_code_url(item: dict[str, Any]) -> str:
    """从 item 里发现 GitHub 代码链接。优先级: raw_json.repo_url > 正则提取 > 空字符串。"""
    # 1. 直接从 raw_json 读（GitHub fetcher 存的）
    raw_json = item.get("raw_json") if isinstance(item.get("raw_json"), dict) else {}
    if raw_json.get("repo_url"):
        return _clean_github_url(raw_json["repo_url"])
    if raw_json.get("html_url") and "github.com" in raw_json["html_url"]:
        return _clean_github_url(raw_json["html_url"])

    # 2. 从 url/canonical_url 检查（GitHub trending 来源的 url 就是仓库 URL）
    url = str(item.get("url") or item.get("canonical_url") or "")
    if "github.com" in url:
        return _clean_github_url(url)

    # 3. 从 summary + content_text 正则提取
    text = " ".join(filter(None, [
        str(item.get("summary") or ""),
        str(item.get("content_text") or ""),
        str(raw_json.get("description") or ""),
    ]))
    match = GITHUB_RE.search(text)
    if match:
        return _clean_github_url(f"https://github.com/{match.group(1)}")

    return ""


def _clean_github_url(url: str) -> str:
    """规范化 GitHub URL：去 query 参数、去尾部标点。"""
    url = url.strip().rstrip(".,;:!?)]}\"'")
    parsed = urlsplit(url)
    query = urlencode([(k, v) for k, v in parse_qsl(parsed.query) if k.lower() not in TRACKING_PARAMS])
    path = parsed.path.rstrip("/")
    return f"https://github.com{path}" if "github.com" in parsed.netloc else url


def extract_repo_key(code_url: str) -> str:
    """从 code_url 提取 org/repo（小写），用于去重。"""
    match = GITHUB_RE.search(code_url)
    if match:
        return match.group(1).lower()
    return ""


def canonicalize_url(url: str | None) -> str:
    """规范化 URL 用于去重。去 tracking 参数。"""
    if not url:
        return ""
    parsed = urlsplit(url.strip())
    query = urlencode([(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True)
                       if k.lower() not in TRACKING_PARAMS and not k.lower().startswith("utm_")])
    scheme = parsed.scheme.lower() or "https"
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/")
    return f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")


def dedup_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """两级去重：URL去重 + repo_key去重。同一 repo 只保留信息最全的一条。"""
    seen_urls: set[str] = set()
    best_by_repo: dict[str, dict[str, Any]] = {}
    result: list[dict[str, Any]] = []

    for item in items:
        url = canonicalize_url(str(item.get("url") or item.get("canonical_url") or ""))
        if url and url in seen_urls:
            continue
        if url:
            seen_urls.add(url)

        code_url = item.get("code_url", "")
        repo_key = extract_repo_key(code_url) if code_url else ""

        if repo_key:
            if repo_key in best_by_repo:
                # 保留信息更全的（有README/summary更长的优先）
                existing = best_by_repo[repo_key]
                if _info_completeness(item) > _info_completeness(existing):
                    best_by_repo[repo_key] = item
                continue
            best_by_repo[repo_key] = item
        else:
            result.append(item)

    result.extend(best_by_repo.values())
    return result


def _info_completeness(item: dict[str, Any]) -> int:
    """评估 item 信息完整度，用于去重时选更全的一条。"""
    score = 0
    if item.get("summary"):
        score += 3
    if item.get("content_text"):
        score += 2
    raw = item.get("raw_json") if isinstance(item.get("raw_json"), dict) else {}
    if raw.get("description"):
        score += 2
    if raw.get("stars"):
        score += 1
    if raw.get("topics"):
        score += 1
    return score
