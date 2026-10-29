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
    conn.commit()


def reset_db(conn: sqlite3.Connection) -> None:
    tables = [
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
