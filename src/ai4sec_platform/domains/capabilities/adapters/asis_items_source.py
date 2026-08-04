from __future__ import annotations
import json, os, urllib.request, urllib.error
from datetime import datetime
from typing import Any


class ASISItemsSource:
    """从 ASIS 拉取资讯 Item, 供能力洞察消费。
    调 ASIS /api/items/export?since=<cursor>&min_score=55, 字段映射成 ai4sec news domain_item 格式,
    让 capability_candidates_from_news + normalize_capability_candidate 能消费。
    """

    def __init__(self, conn, asis_base_url: str | None = None, admin_token: str | None = None):
        self.conn = conn
        self.asis_base_url = (asis_base_url or os.environ.get("ASIS_API_URL") or "http://127.0.0.1:8003").rstrip("/")
        self.admin_token = admin_token or os.environ.get("ASIS_ADMIN_TOKEN") or os.environ.get("ADMIN_TOKEN") or ""
        self._ensure_table()

    def _ensure_table(self):
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS asis_pull_cursor ("
            "id INTEGER PRIMARY KEY, last_since TEXT, last_pull_at TEXT, "
            "last_count INTEGER, last_error TEXT)"
        )
        self.conn.commit()

    def _load_cursor(self) -> str | None:
        row = self.conn.execute("SELECT last_since FROM asis_pull_cursor WHERE id=1").fetchone()
        return row[0] if row else None

    def _save_cursor(self, since: str | None, count: int, error: str | None = None):
        self.conn.execute(
            "INSERT INTO asis_pull_cursor(id, last_since, last_pull_at, last_count, last_error) "
            "VALUES(1, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET last_since=excluded.last_since, "
            "last_pull_at=excluded.last_pull_at, last_count=excluded.last_count, last_error=excluded.last_error",
            (since, datetime.utcnow().isoformat(), count, error),
        )
        self.conn.commit()

    def fetch_since(self) -> list[dict[str, Any]]:
        cursor = self._load_cursor()
        url = f"{self.asis_base_url}/api/items/export?min_score=0&limit=1000&include_status=all"
        if cursor:
            url += f"&since={cursor}"
        req = urllib.request.Request(url, headers={"ADMIN_TOKEN": self.admin_token})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            self._save_cursor(cursor, 0, f"HTTP {exc.code}")
            return []
        except Exception as exc:
            self._save_cursor(cursor, 0, str(exc)[:200])
            return []
        items = data.get("items") or []
        github_items = [it for it in items if "github.com" in (it.get("canonical_url") or "").lower()]
        mapped = [self._map_item(it) for it in github_items]
        next_since = data.get("next_since")
        if next_since:
            self._save_cursor(next_since, len(mapped))
        return mapped

    def _map_item(self, asis_item: dict) -> dict:
        canonical = asis_item.get("canonical_url") or ""
        # A: URL 规范化 - GitHub trending URL 去掉 ?github_trending_date=...&since=daily
        if "github.com" in canonical.lower():
            canonical = canonical.split("?")[0]
        code_url = ""
        if "github.com" in canonical.lower() or "gitlab.com" in canonical.lower():
            code_url = canonical  # 已规范化(去 query 参数)
        elif asis_item.get("paper_url"):
            code_url = asis_item.get("paper_url") or ""
        if "github.com" in canonical.lower():
            source_type = "github"
        elif "arxiv.org" in canonical.lower():
            source_type = "arxiv"
        else:
            source_type = "unknown"
        score = float(asis_item.get("score_total") or 0)
        asis_id = asis_item.get("id")
        summary = asis_item.get("summary") or ""
        # reviewer 期望 source_type = "project"/"paper"(不是 "github"/"arxiv")
        reviewer_type = "project" if source_type == "github" else "paper" if source_type == "arxiv" else "project"
        return {
            "id": f"asis:{asis_id}",
            "item_key": f"asis:{asis_id}",  # reviewer 缓存用
            "title": asis_item.get("title_zh") or asis_item.get("title") or "",
            "source_url": canonical,
            "url": canonical,  # reviewer 读 item.get("url")
            "code_url": code_url,  # reviewer 读 item.get("code_url")
            "source_type": reviewer_type,  # reviewer 读 item.get("source_type"), 期望 "project"/"paper"
            "score": score,
            "summary": summary,  # reviewer 读 item.get("summary")
            "primary_date": asis_item.get("published_at") or asis_item.get("first_seen_at") or "",
            "stars": 0,  # ASIS 没有, reviewer 用 .get() 兜底
            "forks": 0,
            "language": "",
            "raw": {"description": summary},  # reviewer 读 raw.get("description")
            "payload": {
                "code_url": code_url,
                "source_type": source_type,  # 保留原始 "github"/"arxiv" 给 ai4sec 自己用
                "scoring": {"score": score},
                "summary": summary,
                "recommendation_reason": asis_item.get("recommendation_reason") or "",
                "primary_category": asis_item.get("primary_category") or "",
                "sub_category": asis_item.get("sub_category") or "",
                "entities": asis_item.get("entities") or [],
                "paper_url": asis_item.get("paper_url") or "",
                "reader_url": asis_item.get("reader_url") or "",
                "source_system": "asis",
                "asis_id": asis_id,
            },
        }
