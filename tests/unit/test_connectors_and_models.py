from __future__ import annotations

from pathlib import Path

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


def test_llm_router_defaults_to_mock_provider() -> None:
    result = LLMRouter().complete_json(prompt="return json", payload={"hello": "world"})
    assert result["status"] == "mock"
    assert result["payload"] == {"hello": "world"}
