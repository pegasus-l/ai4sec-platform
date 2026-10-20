from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.domains.capabilities.pipelines import (
    capability_conversion_pipeline,
    capability_from_news_pipeline,
    capability_repro_pipeline,
    capability_web_classify_pipeline,
)
from ai4sec_platform.domains.news.pipelines import (
    news_daily_pipeline,
    news_legacy_raw_pipeline,
    news_shadow_collect_pipeline,
)
from ai4sec_platform.domains.threats.pipelines import asset_association_pipeline, huawei_asset_pipeline, huawei_attack_surface_pipeline, huawei_collect_sources_pipeline, huawei_cve_scout_pipeline, huawei_full_migration_pipeline, threat_risk_pipeline
from ai4sec_platform.domains.vulnerabilities.pipelines import comprehension_probe_pipeline, vulnerability_case_ingest_pipeline, vulnerability_batched_full_discovery_pipeline, vulnerability_event_pipeline, vulnerability_external_discovery_pipeline, vulnerability_full_discovery_pipeline, vulnerability_knowledge_pipeline, vulnerability_manual_ingest_pipeline, vulnerability_pattern_pipeline, vulnerability_project_buglist_pipeline, vulnerability_raw_pipeline


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
    registry.register(news_legacy_raw_pipeline())
    registry.register(news_shadow_collect_pipeline())
    registry.register(news_daily_pipeline())
    registry.register(capability_from_news_pipeline())
    registry.register(capability_web_classify_pipeline())
    registry.register(capability_repro_pipeline())
    registry.register(capability_conversion_pipeline())
    registry.register(huawei_collect_sources_pipeline())
    registry.register(huawei_cve_scout_pipeline())
    registry.register(huawei_attack_surface_pipeline())
    registry.register(huawei_asset_pipeline())
    registry.register(huawei_full_migration_pipeline())
    registry.register(threat_risk_pipeline())
    registry.register(asset_association_pipeline())
    vulnerability_raw = vulnerability_raw_pipeline()
    registry.register(vulnerability_raw)
    registry.register_alias("vulnerabilities.material_local_raw_import", vulnerability_raw)
    registry.register(vulnerability_external_discovery_pipeline())
    registry.register(vulnerability_full_discovery_pipeline())
    registry.register(vulnerability_batched_full_discovery_pipeline())
    # 2026-10-16: 「漏洞事件库」改成以洞为主键的案例库(vulnerability_cases), 旧的
    # 「从素材聚合出主题」事件流水线**停止注册**。存量 524 条 event 已在迁移里置 superseded
    # (见 domains/vulnerabilities/legacy_event_migration.py)。
    # 这里只注释掉注册, **函数与模块都保留**(pipelines.py 里的 vulnerability_event_pipeline
    # 与 steps/vulnerability_event.py 不动) —— 回滚就是取消这一行注释 + 把 event 的 status
    # 改回 active, 不需要重新写代码。
    # registry.register(vulnerability_event_pipeline())
    # 2026-10-19 P3: 案例库采集(每日 04:00)。与上面的 event 聚合是两回事 ——
    # 这条是"NVD 窗口 → OSV 富化 → 补丁 diff → 回溯",直接写 vulnerability_cases 表。
    registry.register(vulnerability_case_ingest_pipeline())
    # 2026-10-20 P5b: 项目自有安全源(每日 04:30)。与上面那条是两条 pipeline ——
    # 项目公告慢且可能限流,失败不该拖住核心采集;回滚 = 注释掉这一行。
    registry.register(vulnerability_project_buglist_pipeline())
    registry.register(vulnerability_knowledge_pipeline())
    registry.register(vulnerability_manual_ingest_pipeline())
    registry.register(vulnerability_pattern_pipeline())
    registry.register(comprehension_probe_pipeline())
    return registry
