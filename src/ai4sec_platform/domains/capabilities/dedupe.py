from __future__ import annotations

from typing import Any


def identity_key(item: dict[str, Any]) -> str:
    """生成去重 key，三级 fallback（迁自旧 v1 db.py compute_dedup_key）。

    优先级：
      1. repo URL（github.com/gitlab.com，去尾斜杠和 .git）
      2. arxiv id（从 source_url 提取，格式 arxiv::XXXX.YYYYY）
      3. title（格式 title::完整标题）
    """
    code_url = item.get("code_url") or ""
    source_url = item.get("source_url") or ""

    # 1. repo URL
    for url in [code_url, source_url]:
        if not url:
            continue
        if "github.com" in url or "gitlab.com" in url:
            clean = url.rstrip("/").rstrip(".")
            if clean.endswith(".git"):
                clean = clean[:-4]
            return clean

    # 2. arxiv id
    if "arxiv.org/abs/" in source_url:
        arxiv_id = source_url.split("arxiv.org/abs/")[-1].split("/")[0].split("?")[0]
        if arxiv_id:
            return f"arxiv::{arxiv_id}"
    elif "arxiv.org/pdf/" in source_url:
        arxiv_id = source_url.split("arxiv.org/pdf/")[-1].split("/")[0].replace(".pdf", "")
        if arxiv_id:
            return f"arxiv::{arxiv_id}"

    # 3. title
    title = (item.get("title") or "").strip()
    if title:
        return f"title::{title}"

    return repr(item)


def dedupe_candidates(
    candidates: list[dict[str, Any]],
    *,
    seen_keys: set[str] | None = None,
) -> tuple[list[dict[str, Any]], set[str]]:
    """对候选列表去重。

    返回: (去重后的候选列表, 更新后的 seen_keys 集合)
          seen_keys 用于跨批次去重（传入已有 key 集合，新增的会合并进去）
    """
    if seen_keys is None:
        seen_keys = set()
    result: list[dict[str, Any]] = []
    for candidate in candidates:
        key = identity_key(candidate)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        result.append(candidate)
    return result, seen_keys
