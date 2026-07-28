from __future__ import annotations

from pathlib import Path
import urllib.error

from ai4sec_platform.core.env import load_env_file
from ai4sec_platform.agents.capability_assess import CapabilityAssessAgent
from ai4sec_platform.agents.knowledge_extract import KnowledgeExtractAgent
from ai4sec_platform.agents.risk_reasoning import RiskReasoningAgent
from ai4sec_platform.models.router import LLMRouter
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.registry import SourceRegistry
from ai4sec_platform.sources.connectors.news import base_live


def test_json_source_connector_reads_ai_for_sec_raw() -> None:
    path = Path("/home/liuqi777/ai-for-sec-report/output/raw/arxiv_20260710.json")
    connector = SourceRegistry().get("arxiv")
    result = connector.fetch(SourceFetchRequest(source_name="arxiv", config={"path": str(path)}))
    assert result.errors == []
    assert result.items
    assert result.metadata["path"] == str(path)


def test_json_source_connector_rejects_live_http_fetch_by_default() -> None:
    connector = SourceRegistry().get("arxiv")
    result = connector.fetch(
        SourceFetchRequest(
            source_name="arxiv_live",
            config={"path": "https://export.arxiv.org/api/query?search_query=cat:cs.CR"},
        )
    )
    assert result.items == []
    assert result.errors == ["http_path_not_supported_by_json_file_connector"]


def test_source_retry_uses_exponential_backoff_for_transient_errors(monkeypatch) -> None:
    attempts = 0
    delays: list[float] = []

    def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise TimeoutError("read timed out")
        return "ok"

    monkeypatch.setattr(base_live.random, "uniform", lambda *_args: 0.0)
    monkeypatch.setattr(base_live.time, "sleep", delays.append)
    assert base_live.retry_call(operation) == "ok"
    assert attempts == 3
    assert delays == [1.0, 2.0]


def test_source_retry_does_not_retry_non_transient_http_errors(monkeypatch) -> None:
    attempts = 0

    def operation() -> None:
        nonlocal attempts
        attempts += 1
        raise urllib.error.HTTPError("https://example.com", 402, "Payment Required", {}, None)

    monkeypatch.setattr(base_live.time, "sleep", lambda *_args: None)
    try:
        base_live.retry_call(operation)
    except urllib.error.HTTPError as exc:
        assert exc.code == 402
    else:
        raise AssertionError("HTTP 402 should not be retried")
    assert attempts == 1


def test_llm_router_defaults_to_local_rule_provider() -> None:
    result = LLMRouter().complete_json(prompt="能力评估", payload={"domain": "capabilities", "title": "test github.com/example/repo"})
    assert result["provider"] == "local_rules"
    assert result["status"] == "success"
    assert result["result"]["recommended_status"] == "待复现验证"


def test_llm_router_reads_env_model_config_without_exposing_key() -> None:
    loaded = load_env_file()
    config = LLMRouter().active_config()
    assert "api_key" not in config
    if loaded or config["configured"]:
        assert config["provider"] in {"deepseek", "dashscope", "local_llm", "ai4sec_openai", "local_rules"}


def test_agents_return_rule_results() -> None:
    assert CapabilityAssessAgent().run({"domain": "capabilities", "title": "repo github.com/a/b"})["status"] == "success"
    assert RiskReasoningAgent().run({"domain": "threats", "score": 90})["result"]["recommended_status"] == "高风险跟踪"
    assert KnowledgeExtractAgent().run({"domain": "vulnerabilities", "summary": "CVE 分析"})["result"]["migration_status"] == "待人工确认"
