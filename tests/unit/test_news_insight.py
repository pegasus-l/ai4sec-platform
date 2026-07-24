from __future__ import annotations

import sqlite3

from ai4sec_platform.db.models import init_db
from ai4sec_platform.core.config import PROJECT_ROOT
from ai4sec_platform.domains.news.builders import build_news_items
from ai4sec_platform.domains.news.dedupe import dedupe_normalized_items
from ai4sec_platform.domains.news.normalizers import normalize_raw_item
from ai4sec_platform.domains.news.references import extract_reference_items
from ai4sec_platform.domains.news.tech_map import AgentTechMap
from ai4sec_platform.domains.news.links import resolve_candidate_links
from ai4sec_platform.domains.news.reviewer import _input_hash, _normalize_breakdown, _normalize_deep_review, _normalize_gate, _percentage
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
    assert normalize_raw_item("rss", {"title": "ordinary article", "url": "https://example.com/article"}) is None


def test_tech_map_contract_and_discovery_reference_extraction() -> None:
    tech_map = AgentTechMap.load(PROJECT_ROOT)
    assert len(tech_map.paths) == 72
    valid = tech_map.validate_paths([
        {"dimension": "工具调用", "category": "工具集成总线", "point": "MCP 协议"},
        {"dimension": "工具调用", "category": "虚构分类", "point": "虚构技术"},
    ])
    assert valid == [{"dimension": "工具调用", "category": "工具集成总线", "point": "MCP 协议"}]
    references = extract_reference_items("rss", {"title": "weekly", "summary": "See https://arxiv.org/abs/2501.01234 and https://github.com/acme/scanner"})
    assert {item["source_type"] for item in references} == {"paper", "project"}
    gate = _normalize_gate({"decision": "pass", "map_relevance_score": 88, "potential_value_score": 72, "provisional_tech_paths": valid}, {"title": "MCP"}, tech_map)
    assert gate["decision"] == "pass"
    review = _normalize_deep_review({"score_breakdown": {"map_relevance": 90, "novelty": 80, "technical_depth": 80, "engineering_value": 70, "reproducibility": 70, "influence": 60, "freshness": 80}, "tech_paths": valid}, {"title": "MCP", "source_type": "paper", "gate_review": gate}, tech_map)
    assert review["decision"] == "selected"
    assert review["relevance_score"] == 90
    assert review["score"] == 80.0
    assert _percentage(8) == 8
    assert _percentage(0.7) == 0.7
    assert _percentage(101) == 0
    deepseek_hash = _input_hash({"candidate": {"item_key": "paper:1"}, "model_identity": {"provider": "deepseek", "model": "deepseek-v4-flash"}})
    dashscope_hash = _input_hash({"candidate": {"item_key": "paper:1"}, "model_identity": {"provider": "dashscope", "model": "glm-5.2"}})
    assert deepseek_hash != dashscope_hash
    assert _normalize_breakdown({"engineering_value": 81})["engineering_value"] == 81
    assert _normalize_breakdown({"ability_to_execute": 76})["engineering_value"] == 76
    repeated = tech_map.validate_paths(tech_map.catalog()[:8])
    assert len(repeated) == 8


def test_dedupe_merges_sources_and_complementary_fields() -> None:
    items = dedupe_normalized_items([
        {"item_key": "paper:arxiv:2501.01234", "source": "arxiv", "summary": "", "code_url": "", "authors": ["Ada"]},
        {"item_key": "paper:arxiv:2501.01234", "source": "rss", "summary": "security paper", "code_url": "https://github.com/a/b", "authors": ["Bob"]},
    ])
    assert len(items) == 1
    assert items[0]["summary"] == "security paper"
    assert items[0]["authors"] == ["Ada", "Bob"]
    assert items[0]["discovered_from"] == ["arxiv", "rss"]


def test_explicit_paper_project_links_are_bidirectional() -> None:
    paper = normalize_raw_item("arxiv", {"id": "2501.01234", "title": "Agent Planning", "summary": "agent planning", "code_urls": ["https://github.com/acme/agent"]})
    project = normalize_raw_item("github", {"html_url": "https://github.com/acme/agent", "full_name": "acme/agent", "description": "agent planning", "arxiv_ids": ["2501.01234"]})
    resolved, count = resolve_candidate_links([paper, project])
    assert count == 2
    assert resolved[0]["linked_item_keys"] == ["project:github:acme/agent"]
    assert resolved[1]["linked_item_keys"] == ["paper:arxiv:2501.01234"]


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
    paper["review"] = {"score": 82, "topic": "工具集成总线", "tech_paths": [{"dimension": "工具调用", "category": "工具集成总线", "point": "MCP 协议"}], "technical_points": ["MCP 协议"]}
    project["review"] = {"score": 78, "topic": "长期记忆", "tech_paths": [{"dimension": "记忆与上下文管理", "category": "长期记忆", "point": "RAG / 混合检索"}], "technical_points": ["RAG / 混合检索"]}
    result = build_news_items(conn, [paper, project], run_id="run-1")
    paper_id, project_id = result["item_ids"]
    assert service.list_news(conn, item_type="paper")["total"] == 1
    topics = service.topic_summary(conn)
    assert {topic["topic"] for topic in topics} == {"工具集成总线", "长期记忆"}
    topic = topics[0]
    assert service.list_news(conn, topic=topic["topic"])["total"] == topic["item_count"]
    assert all(item["item_type"] in {"paper", "project"} for item in service.list_news(conn)["items"])
    assert all(item["payload"]["one_liner"] for item in service.list_news(conn)["items"])
    assert service.list_news(conn, tech_dimensions=["工具调用"])["total"] == 1
    assert service.list_news(conn, tech_categories=["长期记忆"])["total"] == 1
    assert service.list_news(conn, tech_points=["MCP 协议", "RAG / 混合检索"], tech_match="any")["total"] == 2
    assert service.list_news(conn, tech_points=["MCP 协议", "RAG / 混合检索"], tech_match="all")["total"] == 0
    counts = service.tech_path_counts(conn)
    assert counts[("工具调用", "工具集成总线", "MCP 协议")] == 1
    assert service.list_news(conn, query="scanner")["items"][0]["id"] == project_id
    state = service.apply_action(conn, paper_id, "bookmark", operator="tester")
    assert state["reading_state"] == "bookmarked"
    assert service.list_news(conn, status="bookmarked", operator="tester")["total"] == 1
    promoted = service.promote_to_capability(conn, project_id, operator="tester")
    assert promoted["status"] == "created"
    assert service.promote_to_capability(conn, project_id, operator="tester")["status"] == "existing"
