from __future__ import annotations

from pathlib import Path

from ai4sec_platform.core.env import load_env_file
from ai4sec_platform.agents.capability_assess import CapabilityAssessAgent
from ai4sec_platform.agents.knowledge_extract import KnowledgeExtractAgent
from ai4sec_platform.agents.risk_reasoning import RiskReasoningAgent
from ai4sec_platform.models.router import LLMRouter
from ai4sec_platform.schemas.sources import SourceFetchRequest
from ai4sec_platform.sources.registry import SourceRegistry


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
