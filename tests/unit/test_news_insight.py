from __future__ import annotations

import sqlite3

from ai4sec_platform.db.models import init_db
from ai4sec_platform.domains.news.builders import build_news_items
from ai4sec_platform.domains.news.dedupe import dedupe_normalized_items
from ai4sec_platform.domains.news.normalizers import normalize_raw_item
from ai4sec_platform.domains.news import service


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    return conn


def test_normalizers_produce_stable_paper_and_project_keys() -> None:
    paper = normalize_raw_item("arxiv", {"id": "https://arxiv.org/abs/2501.01234v2", "title": " Agent Security ", "summary": "  A study  ", "authors": [{"name": "Ada"}]})
    project = normalize_raw_item("github", {"html_url": "https://github.com/Acme/Security-Agent?utm_source=test", "full_name": "Acme/Security-Agent", "description": "scanner", "stargazers_count": 42})
    assert paper["item_key"] == "paper:arxiv:2501.01234"
    assert paper["authors"] == ["Ada"]
    assert project["item_key"] == "project:github:acme/security-agent"
    assert project["source_type"] == "project"
    assert project["stars"] == 42


def test_dedupe_merges_sources_and_complementary_fields() -> None:
    items = dedupe_normalized_items([
        {"item_key": "paper:arxiv:2501.01234", "source": "arxiv", "summary": "", "code_url": "", "authors": ["Ada"]},
        {"item_key": "paper:arxiv:2501.01234", "source": "rss", "summary": "security paper", "code_url": "https://github.com/a/b", "authors": ["Bob"]},
    ])
    assert len(items) == 1
    assert items[0]["summary"] == "security paper"
    assert items[0]["authors"] == ["Ada", "Bob"]
    assert items[0]["discovered_from"] == ["arxiv", "rss"]


def test_builder_is_idempotent_across_runs() -> None:
    conn = connection()
    item = normalize_raw_item("github", {"html_url": "https://github.com/acme/scanner", "full_name": "acme/scanner", "description": "LLM agent security scanner", "stargazers_count": 100})
    first = build_news_items(conn, [item], run_id="run-1")
    item["stars"] = 200
    second = build_news_items(conn, [item], run_id="run-2")
    assert first["created"] == 1
    assert second["updated"] == 1
    assert conn.execute("SELECT COUNT(*) FROM domain_items WHERE domain = 'news'").fetchone()[0] == 1
    assert service.list_news(conn)["items"][0]["project"]["stars"] == 200


def test_news_filters_actions_reports_and_promotion() -> None:
    conn = connection()
    paper = normalize_raw_item("arxiv", {"id": "2501.01234", "title": "Prompt Injection Defense", "summary": "AI security prompt injection defense", "published": "2026-07-20", "authors": ["Ada"]})
    project = normalize_raw_item("github", {"html_url": "https://github.com/acme/scanner", "full_name": "acme/scanner", "description": "agent security scanner", "updated_at": "2026-07-21", "stargazers_count": 500})
    result = build_news_items(conn, [paper, project], run_id="run-1")
    paper_id, project_id = result["item_ids"]
    assert service.list_news(conn, item_type="paper")["total"] == 1
    assert service.list_news(conn, query="scanner")["items"][0]["id"] == project_id
    state = service.apply_action(conn, paper_id, "bookmark", operator="tester")
    assert state["reading_state"] == "bookmarked"
    assert service.list_news(conn, status="bookmarked", operator="tester")["total"] == 1
    promoted = service.promote_to_capability(conn, project_id, operator="tester")
    assert promoted["status"] == "created"
    assert service.promote_to_capability(conn, project_id, operator="tester")["status"] == "existing"
