"""能力候选选择器 - 迁自旧 v1 db.py pick_top_repro_candidates。

选择 top N 复现候选，跳过已成功 / 已活跃的 item。
"""
from __future__ import annotations

from typing import Any

from ai4sec_platform.db import repositories as repo


def select_for_assessment(items: list[dict]) -> list[dict]:
    """保留现有接口兼容：选择有 source_url 或 code_url 的 item"""
    return [item for item in items if item.get("source_url") or item.get("code_url")]


def pick_top_repro_candidates(
    conn,
    *,
    n: int = 3,
    web_only: bool = False,
) -> list[dict[str, Any]]:
    """选择 top N 复现候选。

    排序规则（迁自旧 v1 db.py pick_top_repro_candidates）:
      score DESC + has code_url + primary_date DESC

    跳过规则:
      - 已成功复现的 item（capability_repro_tasks.status in success/partial）
      - 正在复现的 item（status in queued/running）
      - 有 demo_url 的 item（已有在线 demo，不需要复现）
      - web_only=True 时只选 is_web=True 的 item
    """
    succeeded = repo.get_succeeded_repro_item_ids(conn)
    active = repo.get_active_repro_item_ids(conn)
    skip = succeeded | active

    # 拉取能力候选（item_type=capability，按 score DESC）
    items = repo.list_domain_items(conn, "capabilities", item_type="capability", limit=500)

    candidates: list[dict[str, Any]] = []
    for item in items:
        if item["id"] in skip:
            continue

        payload = item.get("payload") or {}

        # web_only 过滤
        if web_only and not payload.get("is_web"):
            continue

        # 有 demo_url 的跳过
        if payload.get("demo_url"):
            continue

        # 必须有 repo URL
        repo_url = _resolve_repo_url(item)
        if not repo_url:
            continue

        item["_repo_url"] = repo_url
        candidates.append(item)
        if len(candidates) >= n:
            break

    return candidates


def _resolve_repo_url(item: dict[str, Any]) -> str:
    """从 item 提取 repo URL（迁自旧 v1 db.py _item_repo_url）"""
    source_url = item.get("source_url") or ""
    code_url = (item.get("payload") or {}).get("code_url") or ""

    if source_url and "github.com" in source_url:
        return source_url
    if code_url:
        return code_url if code_url.startswith("http") else f"https://github.com/{code_url.rstrip('/').rstrip('.')}"
    return source_url or ""
