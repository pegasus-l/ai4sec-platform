from __future__ import annotations

import re
from typing import Any

ARXIV_URL = re.compile(r"https?://(?:www\.)?arxiv\.org/(?:abs|pdf)/(\d{4}\.\d{4,5})(?:v\d+)?(?:\.pdf)?", re.I)
GITHUB_URL = re.compile(r"https?://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)", re.I)


def extract_reference_items(source: str, item: dict[str, Any]) -> list[dict[str, Any]]:
    if source in {"arxiv", "github"}:
        return [item]
    values = [item.get(key) for key in ["url", "paper_url", "code_url", "summary", "description", "text", "content", "title"]]
    values.extend(item.get("reference_urls") or [])
    text = "\n".join(str(value or "") for value in values)
    discovered: list[dict[str, Any]] = []
    seen: set[str] = set()
    for match in ARXIV_URL.finditer(text):
        arxiv_id = match.group(1)
        key = f"paper:arxiv:{arxiv_id}"
        if key in seen:
            continue
        seen.add(key)
        discovered.append({"id": arxiv_id, "title": item.get("title") or f"arXiv {arxiv_id}", "url": f"https://arxiv.org/abs/{arxiv_id}", "paper_url": f"https://arxiv.org/abs/{arxiv_id}", "summary": item.get("summary") or item.get("text") or "", "published": item.get("published") or item.get("published_at") or "", "source_type": "paper", "discovery_context": str(item.get("text") or item.get("summary") or "")[:1000], "discovered_via": source})
    for match in GITHUB_URL.finditer(text):
        owner, repository = match.group(1), match.group(2).removesuffix(".git")
        if repository.lower() in {"issues", "pull", "blob"}:
            continue
        key = f"project:github:{owner.lower()}/{repository.lower()}"
        if key in seen:
            continue
        seen.add(key)
        url = f"https://github.com/{owner}/{repository}"
        discovered.append({"id": key, "title": item.get("title") or f"{owner}/{repository}", "url": url, "repo_url": url, "code_url": url, "repo_full_name": f"{owner}/{repository}", "summary": item.get("summary") or item.get("text") or "", "published_at": item.get("published") or item.get("published_at") or "", "source_type": "project", "discovery_context": str(item.get("text") or item.get("summary") or "")[:1000], "discovered_via": source})
    return discovered


def extract_source_records(records: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    output: list[dict[str, Any]] = []
    metrics: dict[str, int] = {}
    for record in records:
        source = str(record.get("source") or "")
        items = [reference for item in record.get("items") or [] for reference in extract_reference_items(source, item)]
        metrics[source] = len(items)
        output.append({**record, "items": items, "discovery_item_count": len(record.get("items") or []), "reference_item_count": len(items)})
    return output, metrics
