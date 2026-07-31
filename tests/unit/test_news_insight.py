from __future__ import annotations

import sqlite3
import threading
import time

import yaml

from ai4sec_platform.core.time import utc_now
from ai4sec_platform.db import repositories as repo
from ai4sec_platform.db.models import init_db
from ai4sec_platform.core.config import PROJECT_ROOT, Settings
from ai4sec_platform.domains.news.builders import build_news_items
from ai4sec_platform.domains.news.dedupe import dedupe_normalized_items
from ai4sec_platform.domains.news.normalizers import normalize_raw_item
from ai4sec_platform.domains.news.references import extract_reference_items
from ai4sec_platform.domains.news.tech_map import AgentTechMap
from ai4sec_platform.domains.news.links import resolve_candidate_links
from ai4sec_platform.domains.news import reviewer
from ai4sec_platform.domains.news import operations as news_operations
from ai4sec_platform.domains.news.reviewer import _input_hash, _normalize_breakdown, _normalize_deep_review, _normalize_gate, _percentage
from ai4sec_platform.domains.news import service
from ai4sec_platform.domains.news.adapters import sources as source_adapter
from ai4sec_platform.domains.news.adapters.sources import _arxiv_requests, _github_requests
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.connectors.news.asis import AsisConnector
from ai4sec_platform.sources.connectors.news.rss import RssConnector
from ai4sec_platform.sources.connectors.news.awesome import AwesomeConnector
from ai4sec_platform.sources.result import SourceFetchResult


def connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    init_db(conn)
    return conn


def test_live_source_config_matches_legacy_six_source_baseline() -> None:
    config = yaml.safe_load((PROJECT_ROOT / "configs" / "news.yaml").read_text(encoding="utf-8"))["sources"]
    assert list(config) == ["arxiv", "github", "rss", "x", "asis", "awesome"]
    assert config["arxiv"]["categories"] == ["cs.CR", "cs.AI", "cs.SE", "cs.LG", "cs.CL", "cs.MA"]
    assert len(config["arxiv"]["keyword_queries"]) == 37
    assert "mcp-security" in config["github"]["topics"]
    assert len(config["github"]["creation_queries"]) == 9
    assert config["rss"]["feeds"] == [{
        "name": "微信公众号-合并源",
        "url": "http://localhost:8001/feed/all.xml",
        "source_type": "wechat",
        "paginate": True,
        "page_size": 30,
        "article_api_base": "http://localhost:8001/api/v1/wx/articles",
    }]
    assert [account["username"] for account in config["x"]["accounts"]] == ["__suto", "moyix", "halaboratory", "AnthropicAI", "GoogleVRP"]
    assert config["x"]["enabled"] is False
    assert config["x"]["disabled_reason"]
    assert config["asis"]["enabled"] is True
    assert config["awesome"]["repositories"] == ["tmgthb/Autonomous-Agents"]


def test_live_sources_run_with_bounded_concurrency(monkeypatch, tmp_path) -> None:
    active = 0
    max_active = 0
    lock = threading.Lock()

    class FakeConnector:
        def fetch(self, request: SourceFetchRequest) -> SourceFetchResult:
            nonlocal active, max_active
            with lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return SourceFetchResult(source_name=request.source_name, connector_name=request.source_name, items=[{"id": request.source_name}])

    config = {"collection": {"max_workers": 3}, "sources": {source: {"enabled": True} for source in ["rss", "x", "asis"]}}
    monkeypatch.setattr(source_adapter, "_load_config", lambda _root: config)
    monkeypatch.setattr(source_adapter.SourceRegistry, "get", lambda _self, _source: FakeConnector())
    settings = Settings(project_root=PROJECT_ROOT, output_dir=tmp_path, database_path=tmp_path / "test.db", legacy_sources={})
    records = source_adapter.collect_news_sources(settings, {"sources": ["rss", "x", "asis"], "source_workers": 3})
    assert [record["source"] for record in records] == ["rss", "x", "asis"]
    assert max_active == 3


def test_disabled_news_source_is_reported_without_network(monkeypatch, tmp_path) -> None:
    config = {
        "collection": {"max_workers": 1},
        "sources": {"x": {"enabled": False, "disabled_reason": "provider unavailable"}},
    }
    monkeypatch.setattr(source_adapter, "_load_config", lambda _root: config)
    monkeypatch.setattr(source_adapter.SourceRegistry, "get", lambda *_args: (_ for _ in ()).throw(AssertionError("disabled source must not fetch")))
    settings = Settings(project_root=PROJECT_ROOT, output_dir=tmp_path, database_path=tmp_path / "test.db", legacy_sources={})

    records = source_adapter.collect_news_sources(settings, {"sources": ["x"]})

    assert records == [{
        "source": "x",
        "path": "connector:x",
        "exists": True,
        "mode": "shadow",
        "status": "disabled",
        "health": "disabled",
        "items": [],
        "errors": [],
        "metadata": {"disabled": True, "disabled_reason": "provider unavailable"},
    }]


def test_legacy_arxiv_and_github_channels_are_expanded() -> None:
    config = yaml.safe_load((PROJECT_ROOT / "configs" / "news.yaml").read_text(encoding="utf-8"))["sources"]
    arxiv_requests = _arxiv_requests(config["arxiv"], {})
    github_requests = _github_requests(config["github"], {"lookback_days": 7})
    assert [request["category"] for request in arxiv_requests[:6]] == config["arxiv"]["categories"]
    assert sum(bool(request.get("category_backfill")) for request in arxiv_requests) == 6
    assert all(request["max_results"] >= 100 for request in arxiv_requests if request.get("category_backfill"))
    assert any(request.get("keyword") == "MCP model context protocol" and "all:MCP" in request["query"] for request in arxiv_requests)
    assert any(request["channel"] == "new" and request["query"].startswith("topic:fuzzing created:>") for request in github_requests)
    assert any(request["channel"] == "updated" and "stars:>=3" in request["query"] for request in github_requests)
    assert any(request["channel"] == "high_star" and "stars:>5000" in request["query"] for request in github_requests)


def test_werss_pagination_and_article_content_fallback(monkeypatch) -> None:
    first_page = b"""<rss xmlns:content='http://purl.org/rss/1.0/modules/content/'><channel>
      <item><title>Paper</title><link>https://example.com/1</link><description>short</description><content:encoded>See https://arxiv.org/abs/2501.01234</content:encoded></item>
      <item><title>Project</title><link>https://example.com/2</link><description>short</description><id>feed-2</id></item>
    </channel></rss>"""
    second_page = b"""<rss><channel><item><title>Last</title><link>https://example.com/3</link><description>none</description></item></channel></rss>"""
    connector = RssConnector()

    def fake_get_bytes(url: str, **_kwargs) -> bytes:
        if "/api/v1/wx/articles/feed-2" in url:
            return b'{"data":{"content":"See https://github.com/acme/scanner"}}'
        return second_page if "offset=2" in url else first_page

    monkeypatch.setattr(connector, "get_bytes", fake_get_bytes)
    result = connector.fetch(SourceFetchRequest(source_name="rss", config={"feeds": [{"name": "微信公众号-合并源", "url": "http://localhost:8001/feed/all.xml", "source_type": "wechat", "paginate": True, "page_size": 2, "max_pages": 5, "article_api_base": "http://localhost:8001/api/v1/wx/articles"}]}))
    assert result.errors == []
    assert len(result.items) == 3
    assert result.metadata["feeds"][0]["pages"] == 2
    references = [reference for item in result.items for reference in extract_reference_items("rss", item)]
    assert {reference["source_type"] for reference in references} == {"paper", "project"}


def test_werss_incremental_state_filters_seen_articles(monkeypatch) -> None:
    feed = b"""<rss><channel>
      <item><title>Seen</title><link>https://example.com/seen</link><description>old</description></item>
      <item><title>New</title><link>https://example.com/new</link><description>https://github.com/acme/new</description></item>
    </channel></rss>"""
    connector = RssConnector()
    monkeypatch.setattr(connector, "get_bytes", lambda *_args, **_kwargs: feed)
    result = connector.fetch(SourceFetchRequest(
        source_name="rss",
        config={"feeds": [{"url": "http://localhost/feed", "source_type": "wechat", "page_size": 30}]},
        params={"incremental_state": {"scanned_ids": ["rss:wechat:https%3A%2F%2Fexample.com%2Fseen"]}},
    ))
    assert [item["title"] for item in result.items] == ["New"]
    state_ids = result.metadata["next_incremental_state"]["scanned_ids"]
    assert "rss:wechat:https%3A%2F%2Fexample.com%2Fseen" in state_ids
    assert "rss:wechat:https%3A%2F%2Fexample.com%2Fnew" in state_ids


def test_asis_incremental_state_filters_seen_items(monkeypatch) -> None:
    class FakeResponse:
        def __init__(self, content: bytes) -> None:
            self.content = content

        def read(self) -> bytes:
            return self.content

    class FakeOpener:
        def open(self, request, timeout):
            if request.full_url.endswith("/api/auth/login"):
                return FakeResponse(b"ok")
            return FakeResponse(b'{"items":[{"id":1,"title":"Seen","score_total":10},{"id":2,"title":"New","score_total":10},{"title":"Invalid","score_total":10}]}')

    monkeypatch.setenv("ASIS_USERNAME", "operator")
    monkeypatch.setenv("ASIS_PASSWORD", "secret")
    monkeypatch.setattr("ai4sec_platform.sources.connectors.news.asis.urllib.request.build_opener", lambda *_args: FakeOpener())
    result = AsisConnector().fetch(SourceFetchRequest(
        source_name="asis",
        config={"base_url": "https://asis.example", "min_score": 5},
        params={"incremental_state": {"scanned_ids": ["asis:1"]}},
    ))

    assert result.errors == []
    assert [item["id"] for item in result.items] == ["asis:2"]
    assert result.metadata["next_incremental_state"]["scanned_ids"] == ["asis:1", "asis:2"]


def test_awesome_loads_up_to_four_recent_research_subpages(monkeypatch) -> None:
    connector = AwesomeConnector()
    readme = "\n".join(f"[2026-{index}](https://github.com/tmgthb/Autonomous-Agents/blob/main/Research_Papers/2026/page-{index}.md)" for index in range(1, 7))

    def fake_get_bytes(url: str, **_kwargs) -> bytes:
        content = readme if url.endswith("/readme") else "See https://arxiv.org/abs/2501.01234"
        import base64
        import json
        return json.dumps({"content": base64.b64encode(content.encode()).decode()}).encode()

    monkeypatch.setattr(connector, "get_bytes", fake_get_bytes)
    result = connector.fetch(SourceFetchRequest(source_name="awesome", config={"repositories": ["tmgthb/Autonomous-Agents"], "recent_subpage_years": [2026, 2025], "max_subpages": 4}))
    assert result.errors == []
    assert len(result.items) == 5
    assert result.metadata["repositories"][0]["subpages_loaded"] == 4


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
    review = _normalize_deep_review({"score_breakdown": {"map_relevance": 90, "novelty": 80, "technical_depth": 80, "engineering_value": 70, "reproducibility": 70, "influence": 60, "freshness": 80}, "tech_paths": valid, "work_name": "MCPGuard", "theme_descriptor": "面向 Agent 工具调用的协议安全护栏"}, {"title": "MCP", "source_type": "paper", "gate_review": gate}, tech_map)
    assert review["decision"] == "selected"
    assert review["relevance_score"] == 90
    assert review["score"] == 80.0
    assert review["work_name"] == "MCPGuard"
    assert review["theme_descriptor"] == "面向 Agent 工具调用的协议安全护栏"
    assert review["theme"] == "MCPGuard：面向 Agent 工具调用的协议安全护栏"
    legacy_theme = _normalize_deep_review({"score_breakdown": {"map_relevance": 90, "novelty": 80, "technical_depth": 80, "engineering_value": 70, "reproducibility": 70, "influence": 60, "freshness": 80}, "tech_paths": valid, "theme": "ScopeJudge：面向进攻性安全 Agent 的执行前门控系统"}, {"title": "ScopeJudge: Cost-Aware Pre-Execution Gating", "source_type": "paper", "gate_review": gate}, tech_map)
    assert legacy_theme["theme"] == "ScopeJudge：面向进攻性安全 Agent 的执行前门控系统"
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


def test_model_call_retries_transient_errors_only(monkeypatch) -> None:
    class FakeRouter:
        def __init__(self, outcomes):
            self.outcomes = list(outcomes)
            self.calls = 0

        def active_config(self, profile: str):
            return {"provider": "dashscope", "model": "glm-5.2"}

        def complete_json(self, **kwargs):
            self.calls += 1
            outcome = self.outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    conn = connection()
    repo.create_pipeline_run(conn, run_id="retry-run", domain="news", pipeline_name="test.retry", status="running", started_at=utc_now(), finished_at="", production_writes=False, summary={})
    pauses: list[float] = []
    monkeypatch.setattr(reviewer.random, "uniform", lambda *_: 0.0)
    monkeypatch.setattr(reviewer.time, "sleep", pauses.append)
    transient_router = FakeRouter([TimeoutError("read timed out"), TimeoutError("read timed out"), {"provider": "dashscope", "result": {"decision": "pass"}}])
    result, failed = reviewer._call_model(conn, transient_router, run_id="retry-run", agent_name="news_tech_map_gate", model_profile="DASHSCOPE", prompt="gate", input_payload={"candidate": "a"})
    assert not failed
    assert result == {"decision": "pass"}
    assert transient_router.calls == 3
    assert pauses == [1.0, 2.0]
    statuses = [row["status"] for row in conn.execute("SELECT status FROM model_calls ORDER BY id").fetchall()]
    assert statuses == ["retryable_failure", "retryable_failure", "success"]

    permanent_router = FakeRouter([RuntimeError("HTTP Error 401: Unauthorized")])
    result, failed = reviewer._call_model(conn, permanent_router, run_id="retry-run", agent_name="news_deep_review", model_profile="DASHSCOPE", prompt="review", input_payload={"candidate": "b"})
    assert failed
    assert result["attempts"] == 1
    assert permanent_router.calls == 1


def test_concurrent_model_api_returns_per_attempt_audit(monkeypatch) -> None:
    class FakeRouter:
        def __init__(self) -> None:
            self.calls = 0

        def active_config(self, _profile: str) -> dict:
            return {"provider": "dashscope"}

        def complete_json(self, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise TimeoutError("read timed out")
            return {"provider": "dashscope", "result": {"decision": "pass"}}

    monkeypatch.setattr(reviewer.random, "uniform", lambda *_: 0.0)
    monkeypatch.setattr(reviewer.time, "sleep", lambda *_: None)
    result, _output, failed, _provider, _latency, attempts = reviewer._call_model_api(FakeRouter(), model_profile="DASHSCOPE", prompt="gate", input_payload={"candidate": "a"})
    assert not failed
    assert result == {"decision": "pass"}
    assert [attempt["status"] for attempt in attempts] == ["retryable_failure", "success"]


def test_gate_cache_skips_model_and_preserves_input_order(monkeypatch) -> None:
    class CachedOnlyRouter:
        def active_config(self, _profile: str) -> dict:
            return {"provider": "dashscope", "model": "glm-5.2", "base_url": "test"}

        def complete_json(self, **_kwargs):
            raise AssertionError("cached candidates must not call the model")

    monkeypatch.setattr(reviewer, "LLMRouter", CachedOnlyRouter)
    monkeypatch.setattr(reviewer, "_cached_stage", lambda *_args, **_kwargs: {"decision": "pass", "map_relevance_score": 90, "potential_value_score": 80, "provisional_tech_paths": []})
    items = [{"item_key": f"paper:{index}", "title": title, "source_type": "paper"} for index, title in enumerate(["first", "second", "third"])]
    gated, metrics = reviewer.gate_candidates(connection(), items, run_id="cached-run", project_root=PROJECT_ROOT)
    assert [item["title"] for item in gated] == ["first", "second", "third"]
    assert metrics["cache_hits"] == 3
    assert metrics["model_calls"] == 0


def test_news_operations_exposes_domain_scoped_pipeline_metrics() -> None:
    conn = connection()
    repo.create_pipeline_run(conn, run_id="news-ops-run", domain="news", pipeline_name="news.daily_pipeline", status="success", started_at="2026-07-18T08:00:00Z", finished_at="2026-07-18T08:10:00Z", summary={"selected": 12})
    repo.create_task_run(conn, run_id="news-ops-run", step_name="collect_news_sources", metrics={"items": 20})
    repo.create_task_run(conn, run_id="news-ops-run", step_name="gate_news_candidates_with_tech_map", metrics={"candidates": 20, "passed": 12})
    repo.create_model_call(conn, run_id="news-ops-run", agent_name="news_tech_map_gate", model_profile="DASHSCOPE", provider="dashscope", status="success", latency_ms=800)
    repo.create_data_source(conn, domain="news", name="arxiv", source_type="api", status="success", latest_at="2026-07-18T08:00:00Z", health="healthy", summary={"items": 20})
    repo.create_pipeline_run(conn, run_id="threat-run", domain="threats", pipeline_name="threats.test", status="failed")
    conn.commit()

    overview = news_operations.overview(conn)
    assert overview["latest_run"]["run_id"] == "news-ops-run"
    assert overview["models"]["success"] == 1
    assert len(overview["sources"]) == 6
    assert overview["sources"][0]["health"] == "healthy"
    assert overview["sources"][0]["collected_count"] == 20
    x_source = next(source for source in overview["sources"] if source["id"] == "x")
    assert x_source["status"] == "disabled"
    assert x_source["disabled"] is True
    assert x_source["disabled_reason"]
    assert overview["processing"]["collected"] == 20
    assert overview["processing"]["gate_passed"] == 12

    detail = news_operations.run_detail(conn, "news-ops-run")
    assert detail is not None
    gate_task = next(task for task in detail["tasks"] if task["step_name"] == "gate_news_candidates_with_tech_map")
    assert gate_task["metrics"]["passed"] == 12
    assert news_operations.run_detail(conn, "threat-run") is None


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
    paper["review"] = {"score": 82, "topic": "工具集成总线", "work_name": "MCPGuard", "theme_descriptor": "面向 Agent 工具调用的协议安全护栏", "theme": "MCPGuard：面向 Agent 工具调用的协议安全护栏", "tech_paths": [{"dimension": "工具调用", "category": "工具集成总线", "point": "MCP 协议"}], "technical_points": ["MCP 协议"]}
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
    stored_paper = service.list_news(conn, item_type="paper")["items"][0]
    assert stored_paper["payload"]["display_work_name"] == "MCPGuard"
    assert stored_paper["payload"]["display_theme"] == "MCPGuard：面向 Agent 工具调用的协议安全护栏"
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
