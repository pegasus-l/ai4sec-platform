from __future__ import annotations

from ai4sec_platform.pipelines.base import PipelineDefinition
from ai4sec_platform.pipelines.steps.vulnerability_batch import RunBatchedVulnerabilityDiscoveryStep
from ai4sec_platform.pipelines.steps.vulnerability_case_ingest import BackfillEnrichStep, ConsumeCaseSourcesStep, EnrichFromOsvStep, ExtractDataflowStep, ExtractVulnSiteStep, FetchNewCveWindowStep, LinkCasesToMaterialsStep, LinkCasesToProjectsStep, ResolvePatchContextStep
from ai4sec_platform.pipelines.steps.vulnerability_discovery import BuildAcceptedVulnerabilityMaterialsStep, CollectAnySearchCandidatesStep, CrawlCandidatePagesStep, DrillDownAcceptedMaterialsStep, ExtractCrawledContentStep, ReviewCrawledMaterialsStep
from ai4sec_platform.pipelines.steps.vulnerability_event import AggregateVulnerabilityEventsStep
from ai4sec_platform.pipelines.steps.vulnerability_evaluation import BuildVulnerabilityShadowEvaluationStep
from ai4sec_platform.pipelines.steps.vulnerability_raw import BuildVulnerabilityMaterialItemsStep, ImportVulnerabilityRawStep, NormalizeVulnerabilityRawStep
from ai4sec_platform.pipelines.steps.comprehension_probe import ComprehensionProbeStep
from ai4sec_platform.pipelines.steps.vulnerability_knowledge import ExtractVulnerabilityKnowledgeStep, SelectVulnerabilityKnowledgeCandidatesStep
from ai4sec_platform.pipelines.steps.vulnerability_manual import IngestManualMaterialsStep
from ai4sec_platform.pipelines.steps.vulnerability_pattern import SynthesizeVulnerabilityPatternsStep
from ai4sec_platform.pipelines.steps.vulnerability_project_buglist import SyncProjectNativeSourcesStep


def vulnerability_raw_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.material_raw_pipeline",
        domain="vulnerabilities",
        steps=[ImportVulnerabilityRawStep(), NormalizeVulnerabilityRawStep(), BuildVulnerabilityMaterialItemsStep()],
    )


def vulnerability_knowledge_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.knowledge_extraction_pipeline",
        domain="vulnerabilities",
        steps=[SelectVulnerabilityKnowledgeCandidatesStep(), ExtractVulnerabilityKnowledgeStep()],
    )


def vulnerability_manual_ingest_pipeline() -> PipelineDefinition:
    """人工投喂 URL / 文章 → 素材 → 知识候选(2026-10-10)。

    只挂三步:入库 → 选候选 → 抽知识。把 Select/Extract 也挂上,是为了让用户投喂完
    **当场**看到结果 —— Select 会走"只取本 run 刚建的那几个 id"的分支,投喂的素材立刻
    变成知识候选 + 人工复核队列行,不用干等到当晚 22:00 的跑批。

    启动方(API)会显式传 `pending_drain_limit: 0`:兜底排空是给**定时跑批**用的,
    用户喂一条 URL 却连带把 20 条无关积压也抽一遍,既费模型又让人看不懂在跑什么。
    """
    return PipelineDefinition(
        name="vulnerabilities.manual_material_ingest_pipeline",
        domain="vulnerabilities",
        steps=[IngestManualMaterialsStep(), SelectVulnerabilityKnowledgeCandidatesStep(), ExtractVulnerabilityKnowledgeStep()],
    )


def comprehension_probe_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.comprehension_probe_pipeline",
        domain="vulnerabilities",
        steps=[ComprehensionProbeStep()],
    )


def vulnerability_event_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.event_aggregation_pipeline",
        domain="vulnerabilities",
        steps=[AggregateVulnerabilityEventsStep()],
    )


def vulnerability_pattern_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.pattern_synthesis_pipeline",
        domain="vulnerabilities",
        steps=[SynthesizeVulnerabilityPatternsStep()],
    )


def vulnerability_external_discovery_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.external_material_discovery_pipeline",
        domain="vulnerabilities",
        steps=[
            CollectAnySearchCandidatesStep(),
            CrawlCandidatePagesStep(),
            ExtractCrawledContentStep(),
            ReviewCrawledMaterialsStep(),
            DrillDownAcceptedMaterialsStep(),
            BuildAcceptedVulnerabilityMaterialsStep(),
            BuildVulnerabilityShadowEvaluationStep(),
        ],
    )


def vulnerability_full_discovery_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.full_knowledge_discovery_pipeline",
        domain="vulnerabilities",
        steps=[
            CollectAnySearchCandidatesStep(),
            CrawlCandidatePagesStep(),
            ExtractCrawledContentStep(),
            ReviewCrawledMaterialsStep(),
            DrillDownAcceptedMaterialsStep(),
            BuildAcceptedVulnerabilityMaterialsStep(),
            # 2026-10-16: 事件聚合下线(案例库改用 vulnerabilities.* 的新采集流水线)。
            # 这一步是"素材 → 主题 event"的桥梁, 撤掉后知识抽取**不受影响** —— 知识只从
            # material 取, 从不读 event(见 steps/vulnerability_knowledge.py)。
            # 与 registry.py 里的注释是一对: 两处都还原才是完整回滚。
            # AggregateVulnerabilityEventsStep(),
            SelectVulnerabilityKnowledgeCandidatesStep(),
            ExtractVulnerabilityKnowledgeStep(),
            BuildVulnerabilityShadowEvaluationStep(),
        ],
    )


def vulnerability_case_ingest_pipeline() -> PipelineDefinition:
    """案例库的采集链路(2026-10-19 起,P3)。

    步骤之间是依赖关系:没有案例就无从富化,没有引用就认不出补丁,没有补丁就抽不出漏洞点,
    回溯放最后才不会把前面刚收的洞再扫一遍。每日 04:00 由 APScheduler 触发(见 app/main.py),
    与 03:30 的模式合成同用「抢不到全局锁就每 10 分钟重入」的兜底。

    第 1 步 `consume_case_sources`(2026-10-19):读用户在页面上登记的「盯哪些源」
    (生态包 / 单仓 / 指定 id),把 OSV 免费能查到的洞登记进库。它排在最前,是因为
    它建出的 pending CVE 由紧接着的 NVD 窗口步当场补,不用等到下一晚。
    第 6 步 `extract_vuln_site` 是 P4a(2026-10-19):只处理**已经有补丁**的案例,
    所以绝大多数新洞当天到不了这一步 —— 它们要等回溯步把 OSV 的修复链接补上。
    第 7 步 `extract_dataflow` 是 P4b(2026-10-19):只处理**已经抽出漏洞点**的案例,
    它要抓修复前源码并按函数名找 1 跳调用者,是整条链路里最慢的一步(有体积/条数上限)。
    第 8 步 `link_cases_to_projects` 是 P5a(2026-10-19):纯 DB,把这一晚新登记/富化的案例
    按包名与仓库关联到「项目」,只扫 `updated_at` 近 30 天(关联幂等,全量重扫留给项目增改时)。
    第 9 步 `link_cases_to_materials` 是 P6a(2026-10-23):纯 DB,把「文章正文提到这个编号」
    落成案例的 reference 行 —— 这是案例页「相关 writeup」和模式页「实例案例」的数据基础。

    口径(2026-10-19 按实测基线拍板):CVSS ≥ 7.0,**不附加 CWE 条件** ——
    近 7 天 5496 条新 CVE 里 89.3% 都有真 CWE,加这个条件只砍掉 7 条,没有区分度。
    """
    return PipelineDefinition(
        name="vulnerabilities.case_ingest_pipeline",
        domain="vulnerabilities",
        steps=[
            # 盯源排最前:它建出的 pending CVE 案例由紧接着的 NVD 窗口步当场 drain,
            # 不用等到下一晚(用户刚在页面上加的源,当晚就该有结果)。
            ConsumeCaseSourcesStep(),
            FetchNewCveWindowStep(),
            EnrichFromOsvStep(),
            ResolvePatchContextStep(),
            ExtractVulnSiteStep(),
            ExtractDataflowStep(),
            BackfillEnrichStep(),
            # P5a 项目关联排最后:前面几步这一晚新登记/富化的案例,同晚就能在「项目」视图里看到。
            # 纯 DB 不联网,失败也只影响项目视图,不影响采集本身。
            LinkCasesToProjectsStep(),
            # P6a 文章关联(2026-10-23):同样是纯 DB,把「文章提到的洞」写成 reference 行。
            # 放在项目关联之后 —— 它只读素材的 cve_ids 与案例编号,不依赖前 8 步之外的任何东西。
            LinkCasesToMaterialsStep(),
        ],
    )


def vulnerability_project_buglist_pipeline() -> PipelineDefinition:
    """项目自有安全源(P5b,2026-10-20):发布说明 / CHANGELOG / SECURITY.md。

    与 04:00 的案例采集分开跑:这一步逐项目请求第三方页面、慢且可能限流,失败只影响
    「项目公告里提到的洞有没有挂到项目上」,不该拖住核心采集。每日 04:30 + 白名单重入
    (04:00 的主链路常跑到 04:30 之后,抢不到锁就每 10 分钟再来)。

    只做两件事:读项目自己发的文本 → 解析出 CVE/GHSA → **核实存在**才建案例并挂关联。
    查不到的编号不建案例(见 `project_sources` 的诚实性规则)。
    """
    return PipelineDefinition(
        name="vulnerabilities.project_buglist_pipeline",
        domain="vulnerabilities",
        steps=[SyncProjectNativeSourcesStep()],
    )


def vulnerability_batched_full_discovery_pipeline() -> PipelineDefinition:
    return PipelineDefinition(
        name="vulnerabilities.batched_full_knowledge_discovery_pipeline",
        domain="vulnerabilities",
        steps=[RunBatchedVulnerabilityDiscoveryStep()],
    )
