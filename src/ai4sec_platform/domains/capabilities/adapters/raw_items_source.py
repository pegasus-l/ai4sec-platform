"""RawItemsSource——从 ASIS /api/raw-items/export 拉取未经评分的原始数据。
替代旧的 ASISItemsSource，区别：拉 raw_items 表（无score），不是 items 表（有score）。
"""
from __future__ import annotations

import json, os, sqlite3, urllib.request
from datetime import datetime, timezone
from typing import Any


def _env(key: str, default: str = "") -> str:
    val = os.getenv(key)
    if val:
        return val
    # 从 .env 文件读
    try:
        from dotenv import load_dotenv
        load_dotenv("/opt/ai-security-fusion-v2/ai4sec/.env")
        return os.getenv(key, default)
    except Exception:
        return default


class RawItemsSource:
    """从 ASIS 拉取原始信源数据（未经评分）。"""

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.asis_api_url = _env("ASIS_API_URL", "http://127.0.0.1:8003")
        self.asis_admin_token = _env("ASIS_ADMIN_TOKEN", "")
        self._ensure_cursor_table()

    def _ensure_cursor_table(self) -> None:
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS asis_raw_pull_cursor (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_since TEXT,
                last_count INTEGER DEFAULT 0,
                last_pull_at TEXT,
                updated_at TEXT
            )
        """)
        self.conn.execute("INSERT OR IGNORE INTO asis_raw_pull_cursor (id, last_since, last_count, last_pull_at, updated_at) VALUES (1, NULL, 0, NULL, ?)", (datetime.now(timezone.utc).isoformat(),))
        self.conn.commit()

    def get_cursor(self) -> str | None:
        row = self.conn.execute("SELECT last_since FROM asis_raw_pull_cursor WHERE id=1").fetchone()
        return row[0] if row else None

    def update_cursor(self, since: str | None, count: int) -> None:
        self.conn.execute(
            "UPDATE asis_raw_pull_cursor SET last_since=?, last_count=?, last_pull_at=?, updated_at=? WHERE id=1",
            (since, count, datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def fetch_since(self, *, limit: int = 1000) -> list[dict[str, Any]]:
        """增量拉取 ASIS 原始数据。返回映射后的 item 列表。"""
        cursor = self.get_cursor()
        url = f"{self.asis_api_url}/api/raw-items/export?limit={limit}"
        if cursor:
            url += f"&since={cursor}"

        req = urllib.request.Request(url, headers={"ADMIN_TOKEN": self.asis_admin_token} if self.asis_admin_token else {})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
        except Exception as e:
            print(f"[raw-source] fetch error: {e}")
            return []

        items = data if isinstance(data, list) else data.get("items", data.get("data", []))
        mapped = [self._map_item(raw) for raw in items]
        mapped = [m for m in mapped if m]

        # 更新游标（用第一条的 fetched_at，因为 ASIS 按 fetched_at DESC 返回最新在前）
        if items:
            first = items[0]
            new_cursor = first.get("fetched_at") or first.get("published_at") or datetime.now(timezone.utc).isoformat()
            self.update_cursor(new_cursor, len(mapped))

        print(f"[raw-source] fetched {len(items)} raw items, mapped {len(mapped)}")
        return mapped

    def _map_item(self, raw: dict[str, Any]) -> dict[str, Any] | None:
        """ASIS RawItem → ai4sec 候选格式。"""
        raw_json = raw.get("raw_json") or {}
        source_type = raw_json.get("source_type") or "article"
        if source_type == "github":
            source_type = "project"
        elif source_type == "arxiv":
            source_type = "paper"

        title = raw.get("title") or raw_json.get("title") or ""
        if not title:
            return None

        url = raw.get("url") or raw.get("canonical_url") or ""
        summary = raw.get("summary") or raw.get("content_text") or ""
        content_text = raw.get("content_text") or summary

        # 从 raw_json 提取元数据
        repo = raw_json.get("repo") or {}
        stars = raw_json.get("stars") or repo.get("stargazers_count") or 0
        forks = raw_json.get("forks") or repo.get("forks_count") or 0
        language = raw_json.get("language") or repo.get("language")
        topics = raw_json.get("topics") or repo.get("topics") or []
        authors = raw_json.get("authors") or []
        repo_url = raw_json.get("repo_url") or raw_json.get("html_url") or ""
        published_at = raw.get("published_at")

        item_key = f"asis-raw:{raw.get('id') or url}"

        return {
            "item_key": item_key,
            "title": title,
            "summary": summary,
            "content_text": content_text,
            "url": url,
            "canonical_url": raw.get("canonical_url") or url,
            "source_type": source_type,
            "source_url": url,
            "published_at": str(published_at) if published_at else "",
            "primary_date": str(published_at) if published_at else "",
            "stars": int(stars) if stars else 0,
            "forks": int(forks) if forks else 0,
            "language": language,
            "topics": topics if isinstance(topics, list) else [],
            "authors": authors if isinstance(authors, list) else [],
            "code_url": repo_url if "github.com" in str(repo_url).lower() else "",
            "repo_full_name": raw_json.get("repo_full_name") or raw_json.get("full_name") or "",
            "raw": raw_json,
            "raw_json": raw_json,
            "asis_raw_id": raw.get("id"),
        }
