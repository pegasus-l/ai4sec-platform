from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.domains.capabilities.pipelines import capability_assessment_placeholder_pipeline, capability_from_news_pipeline
from ai4sec_platform.domains.news.pipelines import ai_for_sec_raw_pipeline
from ai4sec_platform.domains.threats.pipelines import huawei_raw_pipeline, threat_risk_pipeline
from ai4sec_platform.domains.vulnerabilities.pipelines import vulnerability_knowledge_pipeline, vulnerability_raw_pipeline


class PipelineRegistry:
    def __init__(self) -> None:
        self._pipelines: dict[str, PipelineDefinition] = {}

    def register(self, definition: PipelineDefinition) -> None:
        self._pipelines[definition.name] = definition

    def register_alias(self, alias: str, definition: PipelineDefinition) -> None:
        self.register(PipelineDefinition(name=alias, domain=definition.domain, steps=definition.steps))

    def get(self, name: str) -> PipelineDefinition:
        try:
            return self._pipelines[name]
        except KeyError as exc:
            raise ValueError(f"Unknown pipeline: {name}") from exc

    def list(self) -> list[dict[str, str]]:
        return [{"name": item.name, "domain": item.domain, "steps": str(len(item.steps))} for item in self._pipelines.values()]


def default_registry() -> PipelineRegistry:
    registry = PipelineRegistry()
    news_raw = ai_for_sec_raw_pipeline()
    registry.register(news_raw)
    registry.register_alias("news.ai_for_sec_local_raw_import", news_raw)
    registry.register(capability_assessment_placeholder_pipeline())
    registry.register(capability_from_news_pipeline())
    huawei_raw = huawei_raw_pipeline()
    registry.register(huawei_raw)
    registry.register_alias("threats.huawei_local_raw_import", huawei_raw)
    registry.register(threat_risk_pipeline())
    vulnerability_raw = vulnerability_raw_pipeline()
    registry.register(vulnerability_raw)
    registry.register_alias("vulnerabilities.material_local_raw_import", vulnerability_raw)
    registry.register(vulnerability_knowledge_pipeline())
    return registry
