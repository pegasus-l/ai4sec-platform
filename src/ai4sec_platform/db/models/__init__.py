from __future__ import annotations

import sqlite3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS domain_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    item_type TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    score REAL,
    status TEXT NOT NULL DEFAULT 'active',
    source TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    primary_date TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    metrics_json TEXT NOT NULL DEFAULT '{}',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_domain_items_domain ON domain_items(domain);
CREATE INDEX IF NOT EXISTS idx_domain_items_type ON domain_items(domain, item_type);
CREATE INDEX IF NOT EXISTS idx_domain_items_score ON domain_items(domain, score DESC);


CREATE TABLE IF NOT EXISTS raw_artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT '',
    source_path TEXT NOT NULL DEFAULT '',
    artifact_id INTEGER,
    item_count INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_run ON raw_artifacts(run_id);
CREATE INDEX IF NOT EXISTS idx_raw_artifacts_domain_source ON raw_artifacts(domain, source);

CREATE TABLE IF NOT EXISTS normalized_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    item_key TEXT NOT NULL,
    source TEXT NOT NULL,
    source_type TEXT NOT NULL DEFAULT '',
    title TEXT NOT NULL,
    url TEXT NOT NULL DEFAULT '',
    primary_date TEXT NOT NULL DEFAULT '',
    normalized_json TEXT NOT NULL DEFAULT '{}',
    raw_artifact_id INTEGER,
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY(raw_artifact_id) REFERENCES raw_artifacts(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_normalized_run ON normalized_items(run_id);
CREATE INDEX IF NOT EXISTS idx_normalized_domain ON normalized_items(domain);
CREATE INDEX IF NOT EXISTS idx_normalized_key ON normalized_items(domain, item_key);

CREATE TABLE IF NOT EXISTS evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    domain_item_id INTEGER NOT NULL,
    evidence_type TEXT NOT NULL,
    title TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    confidence REAL,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(domain_item_id) REFERENCES domain_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_evidence_item ON evidence_items(domain_item_id);

CREATE TABLE IF NOT EXISTS pipeline_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL UNIQUE,
    domain TEXT NOT NULL,
    pipeline_name TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    production_writes INTEGER NOT NULL DEFAULT 0,
    summary_json TEXT NOT NULL DEFAULT '{}',
    source_path TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pipeline_runs_domain ON pipeline_runs(domain);

CREATE TABLE IF NOT EXISTS task_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    step_name TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL DEFAULT '',
    finished_at TEXT NOT NULL DEFAULT '',
    metrics_json TEXT NOT NULL DEFAULT '{}',
    error_message TEXT NOT NULL DEFAULT '',
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_task_runs_run_id ON task_runs(run_id);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    bytes INTEGER NOT NULL DEFAULT 0,
    payload_summary_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_artifacts_run_id ON artifacts(run_id);


CREATE TABLE IF NOT EXISTS model_calls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    task_run_id TEXT NOT NULL DEFAULT '',
    agent_name TEXT NOT NULL,
    model_profile TEXT NOT NULL,
    provider TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    input_json TEXT NOT NULL DEFAULT '{}',
    output_json TEXT NOT NULL DEFAULT '{}',
    latency_ms INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES pipeline_runs(run_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_model_calls_run ON model_calls(run_id);
CREATE INDEX IF NOT EXISTS idx_model_calls_agent ON model_calls(agent_name);

CREATE TABLE IF NOT EXISTS data_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    name TEXT NOT NULL,
    source_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unknown',
    latest_at TEXT NOT NULL DEFAULT '',
    health TEXT NOT NULL DEFAULT 'unknown',
    summary_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_data_sources_domain ON data_sources(domain);

CREATE TABLE IF NOT EXISTS quality_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    audit_type TEXT NOT NULL,
    status TEXT NOT NULL,
    score REAL,
    summary TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quality_audits_domain ON quality_audits(domain);

CREATE TABLE IF NOT EXISTS human_queue_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    item_id INTEGER,
    queue_type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    priority INTEGER NOT NULL DEFAULT 3,
    reason TEXT NOT NULL DEFAULT '',
    assignee TEXT NOT NULL DEFAULT '',
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_human_queue_domain ON human_queue_items(domain);

CREATE TABLE IF NOT EXISTS news_item_index (
    canonical_key TEXT PRIMARY KEY,
    domain_item_id INTEGER NOT NULL UNIQUE,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    FOREIGN KEY(domain_item_id) REFERENCES domain_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_news_item_index_item ON news_item_index(domain_item_id);

CREATE TABLE IF NOT EXISTS news_user_states (
    domain_item_id INTEGER NOT NULL,
    operator TEXT NOT NULL DEFAULT 'operator',
    reading_state TEXT NOT NULL DEFAULT 'unread',
    feedback_value TEXT NOT NULL DEFAULT '',
    feedback_reason TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(domain_item_id, operator),
    FOREIGN KEY(domain_item_id) REFERENCES domain_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_news_user_states_operator ON news_user_states(operator, reading_state);

CREATE TABLE IF NOT EXISTS news_daily_reports (
    report_date TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    highlights_json TEXT NOT NULL DEFAULT '[]',
    topic_sections_json TEXT NOT NULL DEFAULT '[]',
    metrics_json TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'shadow',
    run_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capability_repro_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    repo_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    container_name TEXT NOT NULL DEFAULT '',
    workspace_path TEXT NOT NULL DEFAULT '',
    log TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    finished_at TEXT NOT NULL DEFAULT '',
    cleaned_at TEXT NOT NULL DEFAULT '',
    trigger TEXT NOT NULL DEFAULT 'manual',
    report_json TEXT NOT NULL DEFAULT '{}',
    web_port INTEGER,
    web_url TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (item_id) REFERENCES domain_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cap_repro_item ON capability_repro_tasks(item_id);
CREATE INDEX IF NOT EXISTS idx_cap_repro_status ON capability_repro_tasks(status);
CREATE INDEX IF NOT EXISTS idx_cap_repro_created ON capability_repro_tasks(created_at DESC);

CREATE TABLE IF NOT EXISTS threat_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    repo_id INTEGER NOT NULL,
    rel_type TEXT NOT NULL DEFAULT 'related',
    confidence TEXT NOT NULL DEFAULT 'inferred',
    method TEXT NOT NULL DEFAULT 'llm',
    reason TEXT NOT NULL DEFAULT '',
    human_status TEXT NOT NULL DEFAULT 'none',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(asset_id, repo_id, method),
    FOREIGN KEY(asset_id) REFERENCES domain_items(id) ON DELETE CASCADE,
    FOREIGN KEY(repo_id)  REFERENCES domain_items(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_threat_links_asset ON threat_links(asset_id);
CREATE INDEX IF NOT EXISTS idx_threat_links_repo ON threat_links(repo_id);

-- 仓库有效性判定结果(威胁洞察 R4:过滤样例/空壳/镜像仓)。
-- 单独建表而不是改写 domain_items.payload_json:8118 行 payload 各约 100KB,
-- 改写要重写近 800MB,而这里一行只有几十字节;表可由 DROP TABLE 一键回滚。
-- 判定口径的唯一实现在 domains/threats/repo_filter.py,本表只存结论。
CREATE TABLE IF NOT EXISTS threat_repo_filters (
    item_id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL DEFAULT 'threats',
    filtered INTEGER NOT NULL DEFAULT 0,
    code TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    soft INTEGER NOT NULL DEFAULT 0,
    soft_code TEXT NOT NULL DEFAULT '',
    computed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_repo_filters_filtered ON threat_repo_filters(domain, filtered);

-- 威胁洞察 R5:人工添加的采集目标(kind='target',挂到某个既有数据源)
-- 与人工登记、待接入的新数据源(kind='site',还没有采集器,只落库)。
-- 前者会在下一轮采集被 pipelines/steps/threat_sources.py 注入到采集参数里立刻生效。
CREATE TABLE IF NOT EXISTS threat_source_targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL DEFAULT 'target',
    source_key TEXT NOT NULL,
    identifier TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(kind, source_key, identifier)
);
CREATE INDEX IF NOT EXISTS idx_threat_source_targets_kind ON threat_source_targets(kind, source_key, enabled);

-- 人工添加的漏洞检索关键词(2026-10-10)。
-- **为什么要这张表**:漏洞域此前**没有任何写入口** —— 想加检索词只能手改
-- configs/vulnerability_keywords.yaml 再重启容器,而那个 YAML 是 Dockerfile COPY 进镜像的,
-- `compose recreate` 就丢。落库后由 pipelines 在解析完 keyword profile 后**前置合并**
-- (见 domains/vulnerabilities/manual_keywords.py 的 merge_manual_queries)。
-- 与轮换游标(checkpoints/*.json)一样都在 output_dir 卷里,两者都扛 recreate;
-- 选表是因为列表/启停/幂等/留痕都要做,表比 JSON 省事,且 init_db 每次 get_db 都跑,
-- 不需要版本化迁移。
CREATE TABLE IF NOT EXISTS vulnerability_manual_keywords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_name TEXT NOT NULL,
    keyword TEXT NOT NULL COLLATE NOCASE,
    label TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    -- 生效证据(2026-10-16):这条词**最近一次被真正下发**的时刻与被哪个 profile 用上。
    -- 晚于 created_at 说明确实进过某次采集的查询表;空串 = 从未下发。
    -- 为什么要它:挂在没在跑的 profile 上的词"启用"了却永远不会被搜,页面此前只显示
    -- 一个绿色的「启用」徽章,是**看不见的失效**。有这个字段就能显示「从未下发」。
    -- 写入方是 domains/vulnerabilities/manual_keywords.mark_manual_queries_used(),
    -- 只在采集真要下发查询表的那一刻调用。
    last_used_at TEXT NOT NULL DEFAULT '',
    last_used_profile TEXT NOT NULL DEFAULT '',
    UNIQUE(profile_name, keyword)
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_manual_keywords_profile
    ON vulnerability_manual_keywords(profile_name, enabled);

-- ── 漏洞案例库(2026-10-16):「漏洞事件库」从一个**从素材聚合出的主题**改成**一个个单独的洞**。
-- 为什么不复用 domain_items + 新 item_type(这是本次唯一的关键技术选择):
--   ① domain_items 的列表路径恒 `SELECT *`(payload 整列返回),仓库里有"200 条实测 129MB"的
--      踩坑注释(domains/vulnerabilities/service.py:17-28);而领导要的上下文里**有成段代码**
--      (补丁 diff / 漏洞点片段 / 数据流每一跳),塞进 payload_json 就是重演威胁域 800MB 的坑。
--   ② domain_items **没有任何唯一约束**,现有 event 的幂等靠
--      `json_extract(payload_json,'$.aggregation_key')` 扫 JSON 实现的;案例库的主键是
--      外部 id(CVE/GHSA),天然该有 UNIQUE(canonical_id)。
--   ③ 一个洞 → N 个文件/hunk/数据流跳是**一对多**,嵌套数组没法按文件筛、没法分页。
--   ④ domain_items 是四域共用的热表,新域不该往里塞。
-- 表进 SCHEMA_SQL(init_db 每次 get_db 都跑,CREATE TABLE IF NOT EXISTS 即自动迁移,无需版本化)。
CREATE TABLE IF NOT EXISTS vulnerability_cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- 幂等键。取值形态: CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q / OSV-2021-1234 /
    -- oss:<repo>#<issue|commit> / manual:<sha1[:12]>(完全手填、没有外部 id 的项目内部 bug)
    canonical_id TEXT NOT NULL UNIQUE,
    id_kind TEXT NOT NULL DEFAULT 'cve',
    title TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    -- 可空:NULL = 未知,与"算出来是 0 分"是两件事
    cvss_score REAL,
    cvss_vector TEXT NOT NULL DEFAULT '',
    cve_ids_json TEXT NOT NULL DEFAULT '[]',
    ghsa_ids_json TEXT NOT NULL DEFAULT '[]',
    cwe_ids_json TEXT NOT NULL DEFAULT '[]',
    aliases_json TEXT NOT NULL DEFAULT '[]',
    affected_products_json TEXT NOT NULL DEFAULT '[]',
    affected_ranges_json TEXT NOT NULL DEFAULT '[]',
    fixed_versions_json TEXT NOT NULL DEFAULT '[]',
    references_json TEXT NOT NULL DEFAULT '[]',
    -- 从旧 event 继承来的站内素材 id(见 domains/vulnerabilities/legacy_event_migration.py)。
    -- 单独留一列而不是只落 context 行,是为了"删除"时能一眼看出这条案例原来挂在哪些素材上。
    legacy_material_ids_json TEXT NOT NULL DEFAULT '[]',
    -- 外部源的公开/修改时间。modified_at 是**回溯富化的 watermark**:T+7/T+30 后 OSV/GHSA 才
    -- 补上记录,所以采集不是一锤子买卖,每次都按 modified_at 找"该重查的"。
    published_at TEXT NOT NULL DEFAULT '',
    modified_at TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    -- pending_fetch = 人在页面上贴了个 id、等采集步去抓(这**就是**待抓队列,不另建表);
    -- draft = 完全手填但还没写上下文;superseded = 已取代(沿用 event 既有语义,不删行)
    status TEXT NOT NULL DEFAULT 'active',
    -- 4 个位:元数据 / 补丁 / 漏洞点 / 数据流。**由代码统一重算**(cases.refresh_completeness,
    -- 每次写案例/写上下文后自动调),存成列是为了列表页能在 SQL 里直接筛"哪条还没补全",
    -- 不必为每一行去 join 子表 —— 这是本表的常规读路径。
    metadata_complete INTEGER NOT NULL DEFAULT 0,
    has_patch INTEGER NOT NULL DEFAULT 0,
    has_vuln_site INTEGER NOT NULL DEFAULT 0,
    has_dataflow INTEGER NOT NULL DEFAULT 0,
    context_completeness REAL NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL DEFAULT '{}',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_cases_status ON vulnerability_cases(status, severity);
CREATE INDEX IF NOT EXISTS idx_vulnerability_cases_published ON vulnerability_cases(published_at DESC);

-- 一个洞的上下文,**代码全放这张表**(一对多)。
-- provenance 是 NOT NULL 的硬规则:每条上下文都必须说清"这是哪来的",因为
-- from_osv/from_patch = 外部事实,llm_extracted = 模型推断,manual_added = 人写的,
-- 三者在前端要用不同视觉呈现(见计划第七节"诚实性硬规则")。
CREATE TABLE IF NOT EXISTS vulnerability_case_context (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    -- reference(站内素材/外链) / patch_diff / vuln_site / dataflow / caller_snippet / manual_note
    context_type TEXT NOT NULL,
    provenance TEXT NOT NULL,
    -- 仅 provenance='llm_extracted' 必填(写库侧强制,见 cases.add_context)
    confidence REAL,
    repo TEXT NOT NULL DEFAULT '',
    commit_sha TEXT NOT NULL DEFAULT '',
    file_path TEXT NOT NULL DEFAULT '',
    function_name TEXT NOT NULL DEFAULT '',
    start_line INTEGER NOT NULL DEFAULT 0,
    end_line INTEGER NOT NULL DEFAULT 0,
    content TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    source_url TEXT NOT NULL DEFAULT '',
    -- 指向站内 domain_items(material)的行 id,0 = 无。有了它抽屉里点关联 writeup
    -- 可以直接走既有的 openMaterialDrawer,不必把素材正文再抄一份进来。
    ref_item_id INTEGER NOT NULL DEFAULT 0,
    label TEXT NOT NULL DEFAULT '',
    -- dataflow 的跳序 / 同类型多条时的稳定排序
    order_index INTEGER NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    -- 重跑幂等:同一条上下文(同洞同类型同文件同行且内容一样)只落一行。
    -- 写在 UNIQUE 里而不是靠应用层查重,是因为采集/富化/重抽都会反复写同一批行。
    UNIQUE(case_id, context_type, file_path, start_line, content_hash)
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_case_context_case ON vulnerability_case_context(case_id, context_type);

-- "我要盯哪些源"(P3 的采集入口用)。全列照抄 threat_source_targets 的约定与约束,
-- 人工添加的行也在这张表里留痕(created_by/created_at)。
CREATE TABLE IF NOT EXISTS vulnerability_case_sources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    -- tracked_package(生态包) / tracked_repo(单仓) / manual_id(指定 CVE/GHSA)
    kind TEXT NOT NULL DEFAULT 'manual_id',
    source_key TEXT NOT NULL DEFAULT 'manual',
    identifier TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE(kind, source_key, identifier)
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_case_sources_kind ON vulnerability_case_sources(kind, source_key, enabled);

-- P5a 项目维度:一个有名字、可能有多个发布包、有自有公告源的开源项目。
-- 与 vulnerability_case_sources("我要盯哪些零散源")是两件事:项目是可聚合、可展示的实体,
-- 一个项目可以同时被盯源命中,去重仍靠案例的 canonical_id。
-- slug 是身份(github:org/repo),不可编辑;packages_json 是人工确认后的 [{ecosystem,name}],
-- 自动识别只给候选、不直接落库(monorepo 根 manifest 经常不是真正的发布包)。
CREATE TABLE IF NOT EXISTS vulnerability_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    platform TEXT NOT NULL,
    org TEXT NOT NULL DEFAULT '',
    repo TEXT NOT NULL DEFAULT '',
    url TEXT NOT NULL DEFAULT '',
    display_name TEXT NOT NULL,
    packages_json TEXT NOT NULL DEFAULT '[]',
    -- 预留:P5b 的项目自有公告源 ["releases","changelog","github_advisories","issues"]
    native_sources_json TEXT NOT NULL DEFAULT '[]',
    tier TEXT NOT NULL DEFAULT 'benchmark',
    enabled INTEGER NOT NULL DEFAULT 1,
    last_synced_at TEXT,
    sync_cursor_json TEXT,
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_projects_enabled ON vulnerability_projects(enabled, tier);

-- 项目 ↔ 案例。一条案例可以因不同证据挂到同一个项目上(package_match / repo_match 各一行),
-- 所以唯一键带 link_kind;INSERT OR IGNORE 保证每晚重跑不长重复行。
CREATE TABLE IF NOT EXISTS vulnerability_case_projects (
    case_id INTEGER NOT NULL REFERENCES vulnerability_cases(id) ON DELETE CASCADE,
    project_id INTEGER NOT NULL REFERENCES vulnerability_projects(id) ON DELETE CASCADE,
    link_kind TEXT NOT NULL,
    confidence REAL,
    created_at TEXT NOT NULL,
    UNIQUE(case_id, project_id, link_kind)
);
CREATE INDEX IF NOT EXISTS idx_vulnerability_case_projects_project ON vulnerability_case_projects(project_id, case_id);

-- 评审降级待重评队列(2026-10-29)。见 domains/capabilities/review_backlog.py:
-- 模型不可用时 _fallback_review 照样给 decision=watch, 若照旧写库, 一次网关 403 就灌进上千条
-- 没有内容的「待资料补齐」条目(2026-10-28 实测 24 小时 1941 条)。降级候选改落这里, 模型恢复后
-- 由 retry_degraded_reviews 步骤重评。input_json 存的是送模型的那份输入 —— raw 游标每 15 分钟
-- 往前走, 不存就再也拿不回来。
CREATE TABLE IF NOT EXISTS capability_review_backlog (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_key TEXT NOT NULL UNIQUE,
    item_json TEXT NOT NULL DEFAULT '{}',
    input_json TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT NOT NULL DEFAULT '',
    first_seen_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_capability_review_backlog_attempts ON capability_review_backlog(attempts, id);

-- 能力库 E0 有效性等级(2026-11-02)。口径的唯一实现在 domains/capabilities/eval_level.py,
-- 本表只存结论: 平台按复现报告里的证据定级(L0 未验 / L1 构建 / L2 启动 / L3 冒烟 / L4 核心工作流),
-- 被测 agent 不自评。单独建表而不是塞 domain_items.payload_json: 列表页要按条目批量取等级,
-- 而 payload 已经是列表体积的主要来源(2026-10-17 那次 129MB 的教训); 一行几十字节, DROP TABLE 即可回滚。
CREATE TABLE IF NOT EXISTS capability_eval_levels (
    item_id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL DEFAULT 'capabilities',
    e0_level INTEGER NOT NULL DEFAULT 0,
    e0_method TEXT NOT NULL DEFAULT '',
    e0_source TEXT NOT NULL DEFAULT '',
    e0_evidence_json TEXT NOT NULL DEFAULT '{}',
    e0_verified_at TEXT NOT NULL DEFAULT '',
    source_task_id INTEGER,
    computed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cap_eval_level ON capability_eval_levels(e0_level);

-- ---------------------------------------------------------------------------
-- 能力评测 E1 五张表(2026-11-02)。口径见 PRD §8 + 契约 v1。
-- 与 capability_eval_levels(E0)分开: E0 记"跑到哪一步"(能不能起来), 这里记
-- "在标准样本上判得对不对"(判得准不准)。E1 只对已有 E0 等级的条目开放。
--
-- 为什么样本正文不进库: 代码放文件系统、库里只存路径 + sha256。库已经是 15.5GB 的
-- 热表, 40 个源码文件塞进去会把列表接口一起拖慢(2026-10-17 那次 129MB 的教训);
-- 哈希列的另一半用处是判分前核对 —— 评测容器里样本目录只读, 被改过就当场发现,
-- 而不是等指标对不上再回头查。
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS capability_eval_samples (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    category          TEXT NOT NULL,          -- 评测类别, 当前只有 class1_llm_audit
    case_id           INTEGER NOT NULL,       -- vulnerability_cases.id, 只用于追溯
    sample_key        TEXT NOT NULL,          -- 样本编号 s_0001, 与答卷文件名对齐
    pair_key          TEXT NOT NULL,          -- 同一对 pre/post 共用一个键
    polarity          TEXT NOT NULL CHECK (polarity IN ('pre', 'post')),
    artifact_hash     TEXT NOT NULL,          -- 文件正文 sha256
    artifact_path     TEXT NOT NULL,          -- 相对数据集根, 如 samples/s_0001/code.py
    ground_truth_json TEXT NOT NULL CHECK (json_valid(ground_truth_json)),
    published_at      TEXT,                   -- 漏洞公开日, 报表 window 由它算
    valid_until       TEXT,                   -- R12 样本有效期
    created_at        TEXT NOT NULL,
    -- 一对样本只能有一个 pre 和一个 post; 少了 post 就没有误报率可言
    UNIQUE(category, pair_key, polarity),
    UNIQUE(category, sample_key)
);
CREATE INDEX IF NOT EXISTS idx_cap_eval_samples_case
    ON capability_eval_samples(category, case_id);

CREATE TABLE IF NOT EXISTS capability_eval_recipes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id       INTEGER NOT NULL,
    category      TEXT NOT NULL,
    tool_version  TEXT NOT NULL,   -- 冻结时的工具指纹: 工具一改, recipe 立即失效
    recipe_json   TEXT NOT NULL CHECK (json_valid(recipe_json)),
    exploit_note  TEXT NOT NULL DEFAULT '',
    verified_at   TEXT,
    superseded_by INTEGER,         -- 自引用: 重适配后旧 recipe 指向新的, 不删行
    created_at    TEXT NOT NULL,
    UNIQUE(item_id, tool_version)
);
CREATE INDEX IF NOT EXISTS idx_cap_eval_recipes_item
    ON capability_eval_recipes(item_id, category);

CREATE TABLE IF NOT EXISTS capability_eval_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id        INTEGER NOT NULL,
    category       TEXT NOT NULL,
    tool_version   TEXT NOT NULL,
    status         TEXT NOT NULL CHECK (
                       status IN ('running', 'success', 'failed', 'budget_exceeded')),
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    -- R11: 每轮 >=3 次重复并报运行间方差。存进 runs 而不是靠调用方记得传
    repeats        INTEGER NOT NULL DEFAULT 3 CHECK (repeats >= 1),
    -- 预算实际用了多少: 模型调用次数/分钟数与上限分开记, 超支时能说清超在哪
    budget_json    TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(budget_json)),
    cost_json      TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(cost_json)),
    -- PRD §8 的失败枚举: install_failed/build_failed/start_failed/tests_failed/
    -- no_output/needs_paid_key/needs_gpu/needs_external_service/unsupported_os/
    -- repo_unavailable/timeout/resource_limit/agent_gave_up/other; 空串 = 没失败
    failure_reason TEXT NOT NULL DEFAULT '',
    work_dir       TEXT NOT NULL DEFAULT '',   -- 评测容器内的工作目录, 排障用
    created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cap_eval_runs_item
    ON capability_eval_runs(item_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_cap_eval_runs_status
    ON capability_eval_runs(status);

-- L5: 一 run 一个受限模型令牌。评测容器里跑的是第三方工具, 给它一个真 key 等于把 key
-- 交给被测工具; 给它一个只能调平台自己入口、且带次数/token 上限的令牌, 才能既跑得起来
-- 又收得住账。
-- 只存 sha256: 库被读走也拿不到可用的凭证; 明文只在 claim 响应里出现一次。
-- 为什么没有金额列: 网关对未登记价目表的模型一律记 $0.0, 按美元限额等于不限额。
CREATE TABLE IF NOT EXISTS capability_eval_llm_tokens (
    token_hash        TEXT PRIMARY KEY,
    run_id            INTEGER NOT NULL REFERENCES capability_eval_runs(id) ON DELETE CASCADE,
    created_at        TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    max_calls         INTEGER NOT NULL DEFAULT 0,   -- 0 = 不限
    max_tokens        INTEGER NOT NULL DEFAULT 0,   -- 0 = 不限
    calls             INTEGER NOT NULL DEFAULT 0,
    prompt_tokens     INTEGER NOT NULL DEFAULT 0,
    completion_tokens INTEGER NOT NULL DEFAULT 0,
    revoked_at        TEXT
);
CREATE INDEX IF NOT EXISTS idx_cap_eval_llm_tokens_run
    ON capability_eval_llm_tokens(run_id, created_at DESC);

-- 原始答卷(R8 可复现): 工具每轮的输出**逐字**存在这里, 判分只读它、不回写。
-- 单独一张表而不是塞进 results: 答卷在判分之前就到了, 此时 verdict 还不存在;
-- 塞进 results 就得先写一个占位标签, 那就是在库里留下假数据。
-- 放库而不是只放 work_dir, 是因为 work_dir 会被 GC 回收, 而指标要能被重新算一遍。
CREATE TABLE IF NOT EXISTS capability_eval_answers (
    run_id       INTEGER NOT NULL REFERENCES capability_eval_runs(id) ON DELETE CASCADE,
    sample_id    INTEGER NOT NULL REFERENCES capability_eval_samples(id) ON DELETE CASCADE,
    repeat_index INTEGER NOT NULL CHECK (repeat_index >= 0),
    -- 两列是**两件事**, 不能合并(R8): raw_answer 是工具自己的原生输出, 原样存,
    -- 是"它当时到底说了什么"的唯一证据; answer_json 是 parser 翻成契约格式的结果,
    -- 为空表示翻译失败 —— 判分按 invalid_output 算, 而不是拿原生输出硬凑。
    raw_answer   TEXT NOT NULL,
    answer_json  TEXT,
    -- D4-5: 工具自报「这一类样本我不覆盖」(语言/平台不支持)时的原因。
    -- 非空 = 这条**不进分母**, 不是答错、也不是翻译失败。与 answer_json 为空是两件事:
    -- 后者是"它答了但答不成格式", 归工具的分数; 前者是"它明说这事不归它管"。
    excluded_reason TEXT,
    created_at   TEXT NOT NULL,
    UNIQUE(run_id, sample_id, repeat_index)
);

CREATE TABLE IF NOT EXISTS capability_eval_results (
    run_id      INTEGER NOT NULL REFERENCES capability_eval_runs(id) ON DELETE CASCADE,
    sample_id   INTEGER NOT NULL REFERENCES capability_eval_samples(id) ON DELETE CASCADE,
    -- 契约 v1 §4.1 的标签 + 'unstable'。为什么要 unstable: 一个样本跑 >=3 轮,
    -- 三轮回不一样的标签时, 取多数会掩盖抖动、取最好的会美化结果 —— 两种都是
    -- 用规则制造结论。抖动本身就是结论(PRD R11「方差大于差值本身就是结论」),
    -- 所以三轮回不一致就照实标 unstable, 每轮的标签留在 detail_json.per_repeat。
    -- 注意: PRD §8 原来写的是 hit/near_hit/miss/false_positive/refused/error,
    -- 第 1 类以契约 v1 为准(PRD 那句是通用枚举, 落地前的占位)。
    -- 'excluded'(D4-5)是"工具明说这类样本不覆盖", 不是答错: 它不进任何分母。
    -- 单独成一个标签而不再借用 invalid_output —— 借用的话, 报表上"语言不支持"会伪装成
    -- "工具输出不合规", 那是拿我们挑样本的口径去扣工具的分。
    -- 'no_answer'(X15, 2026-11-06)是"扫了但给不出结论": 也不进主分母, 既不是漏报
    -- 也不是"没发现"。以前它被翻译成 found=false, 于是沉默在报表上长成了结论。
    verdict     TEXT NOT NULL CHECK (verdict IN (
                    'strict_hit', 'near_hit', 'other_hunk', 'miss',
                    'false_positive', 'true_negative', 'invalid_output', 'excluded',
                    'no_answer', 'unstable')),
    -- 产出这个 verdict 的那一轮报的位置; unstable 时为空(每轮各自的位置在 detail_json)
    location    TEXT NOT NULL DEFAULT '',
    detail_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail_json)),
    UNIQUE(run_id, sample_id)
);
CREATE INDEX IF NOT EXISTS idx_cap_eval_results_sample
    ON capability_eval_results(sample_id);

CREATE TABLE IF NOT EXISTS capability_eval_reports (
    run_id       INTEGER PRIMARY KEY REFERENCES capability_eval_runs(id) ON DELETE CASCADE,
    -- PRD §8 的硬约束: 报表里没有样本数和时间窗, 就等于让读者自己猜覆盖范围
    metrics_json TEXT NOT NULL CHECK (
                     json_valid(metrics_json)
                     AND json_extract(metrics_json, '$.n_samples') IS NOT NULL
                     AND json_extract(metrics_json, '$.window') IS NOT NULL),
    -- 口径提醒必须写: 空 caveats 的报表比没有报表更糟, 它看起来像结论
    caveats      TEXT NOT NULL CHECK (length(trim(caveats)) > 0),
    created_at   TEXT NOT NULL
);
-- 研究复现: 预筛结果(writeup 复现 T0.1, 2026-11-10)。一条素材一行, **没入选的也留证** ——
-- "这篇为什么不可复现"本身就是结论, 页面要能回答它, 而不是让读者以为没被收进来。
-- 独立建表而不塞 domain_items.payload_json: 素材列表已是库体积主要来源(7.5GB), 这里一行几百字节,
-- 出问题 DROP TABLE 即可回滚。判据的唯一实现在 domains/capabilities/writeup_repro/{screener_rules,screener}.py,
-- 本表只存结论; 结论可复算 = 重跑一遍预筛就能对上。
CREATE TABLE IF NOT EXISTS writeup_repro_candidates (
    material_id     INTEGER PRIMARY KEY,          -- domain_items(id), domain='vulnerabilities'
    screenable      INTEGER NOT NULL DEFAULT 0,   -- 1=可进复现队列
    -- 固定枚举, 新值要改代码不是改数据:
    -- not_writeup|no_poc|poc_unverified|target_unknown|article_incomplete|online_service
    -- poc_unverified 与 no_poc 是两件事: 前者模型说有 PoC 但**原文里找不到那段代码**(编的),
    -- 后者是本来就没有。混在一起会把"模型瞎编"统计成"文章没料"。
    reject_reason   TEXT NOT NULL DEFAULT '',
    has_poc         INTEGER NOT NULL DEFAULT 0,
    poc_lang        TEXT NOT NULL DEFAULT '',
    -- 模型摘出来的 PoC 是否在原文里原样找到。0 = 不可信, 此时一律 screenable=0(不降级放行)
    poc_verified    INTEGER NOT NULL DEFAULT 0,
    target_kind     TEXT NOT NULL DEFAULT 'unknown', -- oss_repo|package|ctf|online_service|self_contained|unknown
    target_repo     TEXT NOT NULL DEFAULT '',     -- 已归一成 github:org/name; 归不了一律空
    target_version  TEXT NOT NULL DEFAULT '',     -- 原文出现过的串, 或 CVE 反查出来的区间(`< 1.2.3`)
    -- 以下三列是 rules-v3(2026-11-11, T1.4 两刀)加的: "正文里出现过某个 CVE"不再等于有目标,
    -- 必须能把编号反查成产品/版本才算。target_source 记录这个目标是谁给的 —— 模型读出来的,
    -- 还是案例库/OSV/NVD 查出来的; 事后要能分开统计"模型抽出来的"和"反查救回来的"。
    target_cve      TEXT NOT NULL DEFAULT '',     -- 模型指认 + 原文校验过的那个洞
    target_product  TEXT NOT NULL DEFAULT '',     -- 反查得到的产品(vendor:product / npm:vite)
    target_source   TEXT NOT NULL DEFAULT '',     -- model|db|osv|nvd; 空 = 没定住目标
    env_hint        TEXT NOT NULL DEFAULT '',
    claimed_effect  TEXT NOT NULL DEFAULT '',     -- 作者声称的效果(一句话)
    evidence_quote  TEXT NOT NULL DEFAULT '',     -- 支撑上面判断的原文原句
    rule_json       TEXT NOT NULL DEFAULT '{}',   -- 规则层结论(可复算)
    screen_json     TEXT NOT NULL DEFAULT '{}',   -- 模型原始输出 + 校验备注(答"它凭什么这么判")
    rule_version    TEXT NOT NULL DEFAULT '',     -- 规则层版本变更后可知哪些行是旧口径
    model_profile   TEXT NOT NULL DEFAULT '',
    screened_by     TEXT NOT NULL DEFAULT 'llm',
    screened_at     TEXT NOT NULL,
    -- 以下四列给 T1.5(按我司资产排优先级)预留, 该步未上线前**恒为空/0**。
    -- 空表示"没算过", 不是"算出来是 P2" —— 用一个能区分这两种状态的默认值。
    asset_hit       INTEGER NOT NULL DEFAULT 0,
    asset_ids       TEXT NOT NULL DEFAULT '[]',
    asset_confidence REAL,
    priority        TEXT NOT NULL DEFAULT '',     -- P0|P1|P2|''(未计算)
    priority_reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_wrc_screenable ON writeup_repro_candidates(screenable, screened_at);
CREATE INDEX IF NOT EXISTS idx_wrc_target     ON writeup_repro_candidates(target_repo);

-- T2.1(2026-11-11): 复现任务。一行 = "把这一篇素材真的跑一遍"。
-- 与候选表分工: 候选回答"这篇值不值得跑"(一次预筛, 可复算); 任务回答"跑了没、算不算成"
-- (有生命周期, 有证据)。候选重筛会重写自己的行, 任务行**不受影响** —— 否则重跑预筛会把
-- 正在跑的任务连带改掉。
--
-- material_id + attempt 上 UNIQUE(2026-11-12 改成复合键): 同一篇素材可以跑多遍, 每遍一行。
-- 重复点"复现"返回**当前这一遍**那行, 不插新行(T2.3 幂等); 要重跑走
-- POST /tasks/{id}/rerun 建下一遍(attempt+1, trigger='rerun'), 不把已完成的记录改回 running
-- —— 否则证据包与结论会对不上。
-- 为什么不是"归档证据 + 重置状态": 会话跑完就 404(opencode 不留 transcript), 重置会把
-- 唯一一次真实执行的记录冲掉, 而"上一次判了 partial、这一次判了 success"本身就是要留的事实。
CREATE TABLE IF NOT EXISTS writeup_repro_tasks (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    material_id      INTEGER NOT NULL,            -- domain_items(id), domain='vulnerabilities'
    attempt          INTEGER NOT NULL DEFAULT 1,  -- 同一素材的第几遍(1 起), 与 material_id 联合唯一
    case_id          INTEGER,                     -- 关联的漏洞案例(vulnerability_cases.id), 可空
    subject_kind     TEXT NOT NULL DEFAULT 'writeup_material',
    -- 复现对象的描述: claim 来自 T1, spec 生成后可被更准确的版本覆盖
    claim            TEXT NOT NULL DEFAULT '',
    claim_quote      TEXT NOT NULL DEFAULT '',
    target_kind      TEXT NOT NULL DEFAULT 'unknown',
    target_repo      TEXT NOT NULL DEFAULT '',
    target_version   TEXT NOT NULL DEFAULT '',
    -- T2.2 的验收标准。放 JSON 而不是拆列: spec 是模型产物 + 人工可编辑, 拆列等于把
    -- 一套还在变的 schema 固化进主键表。要查的字段(claim/target)已在上面对应列冗余。
    spec_json        TEXT NOT NULL DEFAULT '{}',
    spec_source      TEXT NOT NULL DEFAULT '',    -- llm|human; human 优先(文档 §5.3)
    -- 模型说"文章够了"却给不出能对上的引用时的累计次数(网关报错不计)。到上限收 spec_failed:
    -- 那是我们建不出 spec, 不是原文不可复现 —— 单独一个终态, 不和 cannot_repro 混计。
    spec_attempts    INTEGER NOT NULL DEFAULT 0,
    -- 状态机见 domains/capabilities/writeup_repro/tasks.py: 非法迁移直接抛错, 不静默写
    status           TEXT NOT NULL DEFAULT 'pending',
    -- verdict 与 failure_reason 必须成对(§7.2)。cannot_repro = 原文的锅, failed = 我们的锅,
    -- 两者混着统计,"原文不可复现"会被读成"我们做不出来"
    verdict          TEXT NOT NULL DEFAULT '',    -- success|partial|cannot_repro|failed|blocked
    failure_reason   TEXT NOT NULL DEFAULT '',    -- probe_not_matched|review_conflict|degraded|
                                                  -- article_incomplete|version_mismatch|env_error|online_target
    review_verdict   TEXT NOT NULL DEFAULT '',    -- 人工复核结论
    review_reason    TEXT NOT NULL DEFAULT '',
    recipe_id        INTEGER,                     -- T4 的 recipe(writeup_repro_recipes), 未上线恒空
    container_name   TEXT NOT NULL DEFAULT '',
    session_id       TEXT NOT NULL DEFAULT '',
    evidence_json    TEXT NOT NULL DEFAULT '{}',  -- 判定依据(命令输出片段/截图路径/校验结果)
    recipe_json      TEXT NOT NULL DEFAULT '{}',  -- 这次实际怎么跑起来的(可复用成 recipe)
    log              TEXT NOT NULL DEFAULT '',
    duration_seconds INTEGER,
    tool_calls       INTEGER,
    trigger          TEXT NOT NULL DEFAULT 'manual', -- manual|pipeline|rerun
    created_by       TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL DEFAULT '',
    finished_at      TEXT,
    cleaned_at       TEXT,
    UNIQUE(material_id, attempt)
);
CREATE INDEX IF NOT EXISTS idx_wrt_status   ON writeup_repro_tasks(status, id);
CREATE INDEX IF NOT EXISTS idx_wrt_verdict  ON writeup_repro_tasks(verdict, id);
CREATE INDEX IF NOT EXISTS idx_wrt_material ON writeup_repro_tasks(material_id);

-- T4.3(2026-11-13): 八节复现报告。一份任务一份报告, task_id 就是主键。
-- 报告是**证据文档**, 所以它把八节拆成 JSON 列存, 页面按模板渲染成中文 ——
-- 存散文的话, 下游抽 recipe/pattern 还得再解析一遍(实施文档 §13.2)。
-- 第 1/2/3/4 节由规则写, 第 5/6/7 节由模型写 + 规则校验, 第 8 节两边相加;
-- 谁写的记在各 JSON 的 speaker 字段里(作者声称 / 我们跑的 / 模型推的, 永不混写)。
-- caveats 上 CHECK 非空: 一份说不出"哪些是推断"的报告, 读者会默认它全都核对过。
-- 模型报错时**一行都不写** —— 半份报告会被读成"5/6/7 节就是空的"(§13.8)。
-- 历史行不重写: 重新生成走 ON CONFLICT(task_id) 覆盖同一行(不含半旧半新)。
CREATE TABLE IF NOT EXISTS writeup_repro_reports (
    task_id          INTEGER PRIMARY KEY,          -- writeup_repro_tasks.id, 一份任务一份
    material_id      INTEGER NOT NULL,             -- domain_items(id), 便于按素材回查
    verdict          TEXT NOT NULL,                -- success|partial|cannot_repro|failed|blocked
    failure_reason   TEXT NOT NULL DEFAULT '',     -- 与 verdict 成对(§7.2), success 时为空
    claim_json       TEXT NOT NULL DEFAULT '{}',   -- 第 2 节: 作者声称(原文 + 引句)
    observed_json    TEXT NOT NULL DEFAULT '{}',   -- 第 4 节: 实测现象 + probe 命中
    attribution_json TEXT NOT NULL DEFAULT '{}',   -- 第 5 节: 归因 + 指向第 3 节的条目编号
    root_cause_json  TEXT NOT NULL DEFAULT '{}',   -- 第 6 节: 漏洞点/不变量/校验结果
    pattern_json     TEXT NOT NULL DEFAULT '{}',   -- 第 7 节: 三种形态 + 泛化边界 + provenance
    evidence_json    TEXT NOT NULL DEFAULT '{}',   -- 第 3 节(命令表) + 完整证据包 + 生成元信息
    caveats          TEXT NOT NULL CHECK (length(trim(caveats)) > 0),  -- 第 8 节, JSON 数组
    generated_by     TEXT NOT NULL,                -- rules|llm|hybrid
    reviewed_by      TEXT,                         -- T4.2 复核 agent / 人工
    reviewed_at      TEXT,
    created_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wrr_verdict ON writeup_repro_reports(verdict, task_id);
CREATE INDEX IF NOT EXISTS idx_wrr_material ON writeup_repro_reports(material_id);
"""


def init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_SQL)
    # Migrations
    try: conn.execute("ALTER TABLE domain_items ADD COLUMN last_synced_at TEXT")
    except Exception: pass
    try: conn.execute("ALTER TABLE human_queue_items ADD COLUMN queue_source TEXT DEFAULT 'pipeline'")
    except Exception: pass
    # 生效证据两列(2026-10-16):生产库那张表 10-10 就建好了,上面的 CREATE TABLE IF NOT EXISTS
    # **补不了列**,只能走这里。init_db 每次 get_db 都跑,所以必须幂等 —— duplicate column
    # 的报错由同一个 except 吞掉,与上面两条同风格。
    try: conn.execute("ALTER TABLE vulnerability_manual_keywords ADD COLUMN last_used_at TEXT NOT NULL DEFAULT ''")
    except Exception: pass
    try: conn.execute("ALTER TABLE vulnerability_manual_keywords ADD COLUMN last_used_profile TEXT NOT NULL DEFAULT ''")
    except Exception: pass
    # e0_source(2026-11-02): 同上, 表 11-02 已经建过, CREATE TABLE IF NOT EXISTS 补不了列。
    try: conn.execute("ALTER TABLE capability_eval_levels ADD COLUMN e0_source TEXT NOT NULL DEFAULT ''")
    except Exception: pass
    # excluded_reason(2026-11-02, D4-5): 答案表已建过, 同上只能补列。
    try: conn.execute("ALTER TABLE capability_eval_answers ADD COLUMN excluded_reason TEXT")
    except Exception: pass
    # target_cve / target_product / target_source(2026-11-11, rules-v3): 同上, 表 11-10 已建过,
    # CREATE TABLE IF NOT EXISTS 补不了列。
    try: conn.execute("ALTER TABLE writeup_repro_candidates ADD COLUMN target_cve TEXT NOT NULL DEFAULT ''")
    except Exception: pass
    try: conn.execute("ALTER TABLE writeup_repro_candidates ADD COLUMN target_product TEXT NOT NULL DEFAULT ''")
    except Exception: pass
    try: conn.execute("ALTER TABLE writeup_repro_candidates ADD COLUMN target_source TEXT NOT NULL DEFAULT ''")
    except Exception: pass
    _migrate_results_verdict_labels(conn)
    _migrate_writeup_task_attempt(conn)
    conn.commit()


def _writeup_tasks_ddl() -> str:
    """从 ``SCHEMA_SQL`` 里取出 ``writeup_repro_tasks`` 的建表语句与它的索引。

    重建表时**直接复用这一份**, 不在迁移里再抄一遍 40 列 —— 抄一份就一定会漂(列加在
    SCHEMA_SQL 里、忘了加到迁移里, 重建完就少一列, 而且是静默少列)。
    """
    import re

    table = re.search(r"CREATE TABLE IF NOT EXISTS writeup_repro_tasks \(.*?\n\);", SCHEMA_SQL, re.S)
    if table is None:  # pragma: no cover - 只有改了 SCHEMA_SQL 的写法才会走到
        raise RuntimeError("SCHEMA_SQL 里找不到 writeup_repro_tasks 的建表语句")
    indexes = re.findall(
        r"CREATE INDEX IF NOT EXISTS idx_wrt_\w+\s+ON\s+writeup_repro_tasks\([^)]*\);", SCHEMA_SQL
    )
    if len(indexes) < 3:  # pragma: no cover - 同上, 防止正则悄悄少匹配一条
        raise RuntimeError(f"SCHEMA_SQL 里 writeup_repro_tasks 的索引数不对: {len(indexes)}")
    return table.group(0) + "\n" + "\n".join(indexes)


def _migrate_writeup_task_attempt(conn: sqlite3.Connection) -> None:
    """把 ``writeup_repro_tasks`` 的 ``UNIQUE(material_id)`` 换成 ``UNIQUE(material_id, attempt)``。

    2026-11-12 用户拍板的重跑口径: 同一篇素材可以跑第 2、第 3 遍, 每遍一行、各留各的证据。
    原来的单列 UNIQUE 让终态任务**跑不了第二遍**(`/run` 直接 400), 而会话跑完就 404
    (opencode 不留 transcript), 重跑是唯一能让一条已被判错的任务重新出结论的路径。

    SQLite 的列级 ``UNIQUE`` 建的是自动索引, **删不掉**, 只能重建表。判据读建表语句而不是
    版本号(与 `_migrate_results_verdict_labels` 同一口径): 没有 `UNIQUE(material_id, attempt)`
    就是要补。表里只有几十行, 重建是毫秒级操作。
    """
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='writeup_repro_tasks'"
    ).fetchone()
    if row is None or "UNIQUE(material_id, attempt)" in (row[0] or ""):
        return
    conn.execute("ALTER TABLE writeup_repro_tasks RENAME TO writeup_repro_tasks_old")
    # 索引跟着被改名的表走、**名字还占着**, 不先删掉的话下面 `CREATE INDEX IF NOT EXISTS`
    # 会被静默跳过, 等 DROP 旧表时索引一起消失 —— 新表就成了没有索引的表。
    for (index_name,) in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='writeup_repro_tasks_old'"
        " AND name NOT LIKE 'sqlite_autoindex%'"
    ).fetchall():
        conn.execute(f"DROP INDEX IF EXISTS {index_name}")
    conn.executescript(_writeup_tasks_ddl())
    old_cols = [r[1] for r in conn.execute("PRAGMA table_info(writeup_repro_tasks_old)").fetchall()]
    new_cols = [r[1] for r in conn.execute("PRAGMA table_info(writeup_repro_tasks)").fetchall()]
    # 旧表没有 attempt 列 ⇒ 存量行一律是第 1 遍, 交给列的 DEFAULT 1。
    shared = ", ".join(c for c in new_cols if c in old_cols)
    conn.execute(
        f"INSERT INTO writeup_repro_tasks ({shared}) SELECT {shared} FROM writeup_repro_tasks_old"
    )
    conn.execute("DROP TABLE writeup_repro_tasks_old")


def _migrate_results_verdict_labels(conn: sqlite3.Connection) -> None:
    """把 `capability_eval_results.verdict` 的 CHECK 补上 'excluded'(D4-5)与
    'no_answer'(X15, 2026-11-06)。

    CHECK 不能 ALTER, 只能重建表。**只在旧表结构上跑**: 新建库走 `SCHEMA_SQL` 就已经带
    两个标签, 这里是给"库里已经有这张表"的环境补的。判据直接读建表语句, 不看版本号 ——
    版本号这种东西没人维护, 而建表语句就是事实。

    判据用 `'no_answer'`: 它是后加的那个, 没有它就说明这张表还没补过。漏掉这步的后果
    不是少一个标签 —— INSERT 会撞 CHECK, 整轮判分在写结果那一步失败。

    这张表每个 run 只有几十行(样本数), 重建是一次毫秒级操作, 不碰其它表。
    """
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table'"
                       " AND name='capability_eval_results'").fetchone()
    if row is None or "'no_answer'" in (row[0] or ""):
        return
    conn.executescript(
        """
        CREATE TABLE capability_eval_results_new (
            run_id      INTEGER NOT NULL REFERENCES capability_eval_runs(id) ON DELETE CASCADE,
            sample_id   INTEGER NOT NULL REFERENCES capability_eval_samples(id) ON DELETE CASCADE,
            verdict     TEXT NOT NULL CHECK (verdict IN (
                            'strict_hit', 'near_hit', 'other_hunk', 'miss',
                            'false_positive', 'true_negative', 'invalid_output', 'excluded',
                            'no_answer', 'unstable')),
            location    TEXT NOT NULL DEFAULT '',
            detail_json TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(detail_json)),
            UNIQUE(run_id, sample_id)
        );
        INSERT INTO capability_eval_results_new
            (run_id, sample_id, verdict, location, detail_json)
            SELECT run_id, sample_id, verdict, location, detail_json
            FROM capability_eval_results;
        DROP TABLE capability_eval_results;
        ALTER TABLE capability_eval_results_new RENAME TO capability_eval_results;
        CREATE INDEX IF NOT EXISTS idx_cap_eval_results_sample
            ON capability_eval_results(sample_id);
        """
    )


def reset_db(conn: sqlite3.Connection) -> None:
    tables = [
        # 能力评测 E1: 子先父后
        "capability_eval_reports",
        "capability_eval_results",
        "capability_eval_answers",
        "capability_eval_runs",
        "capability_eval_samples",
        "capability_eval_recipes",
        "threat_links",
        "threat_repo_filters",
        "threat_source_targets",
        "vulnerability_manual_keywords",
        # 案例库五张表: context/projects 链接有外键级联, DROP 顺序仍按"子先父后"写清楚
        "vulnerability_case_projects",
        "vulnerability_case_context",
        "vulnerability_case_sources",
        "vulnerability_projects",
        "vulnerability_cases",
        "news_daily_reports",
        "news_user_states",
        "news_item_index",
        "capability_repro_tasks",
        "human_queue_items",
        "quality_audits",
        "normalized_items",
        "raw_artifacts",
        "data_sources",
        "model_calls",
        "artifacts",
        "task_runs",
        "pipeline_runs",
        "evidence_items",
        "domain_items",
    ]
    for table in tables:
        conn.execute(f"DROP TABLE IF EXISTS {table}")
    conn.commit()
    init_db(conn)
