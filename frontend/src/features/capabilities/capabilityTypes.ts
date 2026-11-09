export type CapabilityView = 'today' | 'library' | 'repro' | 'conversion' | 'eval' | 'ops-overview' | 'ops-quality' | 'ops-runs';

// ========== 能力评测(E1) ==========
// 与 E0(复现跑没跑起来)是两件事: E0 回答"能不能起来", E1 回答"在标准样本上判得准不准"。
// 页面上必须分开写, 否则读者会把 E0 的等级当成准确率。

/** 一个指标: value 是各轮的中位数, ci95 是"各轮中位数"的区间(不是单轮的样本区间)。
 *  value 为 null 表示**没算出来**, 不是 0 —— 页面直接显示「—」, 不补零。 */
export interface EvalMetric {
  value: number | null;
  ci95: [number | null, number | null] | null;
  values: number[];
  /** 各轮数值是否完全相同。false 说明这份分数对随机性敏感, 不能拿去和别的工具比一次输赢。 */
  identical?: boolean | null;
}

/** 报表摘要(后端 _headline)。所有数字原样来自 score.py, 前端不二次计算。 */
export interface EvalHeadline {
  n_samples: number | null;
  /** 被工具声明为"不覆盖"、未计入分母的样本数(D4-5)。 */
  n_excluded: number | null;
  excluded_reasons: Record<string, number>;
  window: { start?: string | null; end?: string | null; missing?: number } | null;
  adaptation_verdict: string | null;
  repeats: number;
  locate_rate: EvalMetric;
  strict_locate_rate: EvalMetric;
  false_positive_rate: EvalMetric;
  balanced_accuracy: EvalMetric;
}

export interface EvalRunSummary {
  run_id: number;
  status: string;
  tool_version: string | null;
  started_at: string;
  finished_at: string | null;
  repeats: number;
  failure_reason: string | null;
  /** null = 这一轮没有报表(失败/预算超限/还在跑), 不等于"跑出来是 0 分"。 */
  metrics: EvalHeadline | null;
  caveats: string;
}

export interface EvalTool {
  item_id: number;
  title: string;
  status: string;
  e0: { level: number; method: string | null; source: string | null; verified_at: string | null };
  /** null = **尚未评测**。页面必须与"评测失败"分开写, 否则"没被评"会被读成"评了不行"。 */
  latest_run: EvalRunSummary | null;
}

export interface EvalCategory {
  id: string;
  name: string;
  contract_version: string;
  /** 这一类测的是什么。 */
  what: string;
  /** 这一类**测不出**什么。 */
  cannot: string;
  n_samples: number;
  n_runs: number;
}

/** 逐样本结论。verdict 取值见契约 §4.1: strict_hit / near_hit / other_hunk / miss /
 *  false_positive / true_negative / invalid_output / excluded。 */
export interface EvalSampleResult {
  sample_id: number;
  sample_key: string;
  polarity: string;
  verdict: string;
  location: unknown;
  per_repeat: Array<Record<string, unknown>>;
}

export interface EvalToolDetail {
  item_id: number;
  title: string;
  status: string;
  category: string;
  e0: { level: number; method: string | null; source: string | null; verified_at: string | null } | null;
  runs: Array<{
    id: number; status: string; tool_version: string | null; started_at: string;
    finished_at: string | null; repeats: number; failure_reason: string | null;
  }>;
  latest: null | {
    run: Record<string, unknown> & { id: number; status: string; caveats: string; report: EvalHeadline | null };
    metrics: EvalHeadline | null;
    results: EvalSampleResult[];
  };
  /** 这份分数**回答不了**的问题。页面上一律不折叠 —— 没有边界说明的准确率, 读者一定会外推。 */
  cannot_answer: string[];
}

export interface CapabilityItem {
  id: number;
  title: string;
  summary: string;
  source_url: string;
  score: number;
  status: string;
  tags: string[];
  payload: {
    assessment?: Record<string, unknown>;
    capability_scoring?: Record<string, unknown>;
    score_reason?: string;
    overview?: string;
    security_value?: string;
    reproducibility_assessment?: string;
    code_quality?: string;
    application_advice?: string;
    code_url?: string;
    source_type?: string;
    capability_type?: string;
    sub_type?: string;
    application_scenarios?: string[];
    tech_points?: string[];
    repro_status?: string;
    repro_result?: unknown;
    /** repro_status==='not_supported'(无需复现)的原因: non_web=项目不是 Web / env_unsupported=依赖 Docker 等本环境没有的条件 */
    repro_skip_reason?: 'non_web' | 'env_unsupported';
    conversion_status?: string;
    is_web?: boolean;
    web_framework?: string;
    demo_url?: string;
    implementation_depth?: {
      has_real_code: boolean;
      has_tests: boolean;
      has_eval: boolean;
      is_prompt_wrapper?: boolean;
      is_thin_mcp_wrapper?: boolean;
    };
    score_breakdown?: Record<string, number>;
    source_news_score?: number;
    repro_report?: ReproReport;
    repro_summary?: string;
    summary?: string;
    highlight?: string;
    theme?: string;
    pitch?: string;
    display_topic?: string;
    display_theme?: string;
    display_work_name?: string;
    display_title?: string;
    display_summary?: string;
    one_liner?: string;
    usage?: Record<string, string>;
    blockers?: string[];
    gotchas?: string[];
    source_news_item?: Record<string, unknown>;
  };
  metrics?: Record<string, unknown>;
  /** E0 有效性等级(列表带等级, 详情带完整证据链) */
  e0?: E0Level;
}

export interface ReproReport {
  level?: string;
  status: string;
  summary: string;
  /** status=partial 时 agent 必须写清哪一部分有问题(缺了页面会显式提示未说明) */
  partial_reason?: string;
  /** L1 构建证据: 实际命令 + 真实退出码 + 产物路径 */
  build?: { command?: string; exit_code?: number; artifact?: string };
  project_type?: string;
  environment?: Record<string, unknown>;
  steps?: Array<{ cmd: string; ok: boolean; note?: string }>;
  run_result?: Record<string, unknown>;
  blockers?: string[];
  gotchas?: string[];
  usage?: Record<string, string>;
  is_web?: boolean;
  web_started?: boolean;
  web_framework?: string;
  start_command?: string;
  verify?: string;
  core_workflow?: {
    goal?: string;
    mode?: 'real' | 'mock' | string;
    steps?: Array<string | { action?: string; ok?: boolean }>;
    evidence?: string[];
    result?: string;
    verified?: boolean;
  };
  acceptance_issues?: string[];
  page_check?: {
    ok?: boolean | null;
    method?: string;
    entry?: string;
    entry_status?: number | null;
    entry_type?: string;
    visible_chars?: number;
    resources_checked?: number;
    failed?: string[];
    issues?: string[];
  };
  tests?: {
    framework?: string;
    command?: string;
    result?: string;
    totals?: { passed?: number; failed?: number; skipped?: number };
    fixed?: string[];
    failed_tests?: string[];
    notes?: string;
  };
}

/** E0 有效性等级的一级证据(平台按复现报告算, 见后端 domains/capabilities/eval_level.py) */
export interface E0Rung {
  level: number;
  name: string;
  /** true=通过 / false=没通过 / null=报告里没有这一级的证据 */
  ok: boolean | null;
  /** 这一级的证据是谁采的: platform=平台自己采的(目前只有 page_check) / agent=agent 写进报告的 */
  owner?: 'platform' | 'agent' | string;
  source?: string;
  detail?: string;
}

export interface E0Level {
  e0_level: number;
  e0_label: string;
  /** contract=2026-10-31 起的结构化证据口径(阶梯严格累积); backfill=历史报告(封顶 L3) */
  e0_method?: 'contract' | 'backfill' | string;
  e0_method_label?: string;
  /** 证据来源(与 e0_method 正交): agent_only=全在 agent 报告里 / platform_page=用到了平台页面自检
   *  / platform_replay=用到了平台重放(未上线)。等级相同、来源不同, 证据的分量不同。 */
  e0_source?: 'agent_only' | 'platform_page' | 'platform_replay' | string;
  e0_source_label?: string;
  e0_verified_at?: string;
  source_task_id?: number | null;
  /** 以下三项只有详情端点返回(列表只带等级, 证据链 1~2KB 不塞进列表) */
  rungs?: E0Rung[];
  caveats?: string[];
  missing?: string[];
}

export interface ReproTask {
  id: number;
  task_id?: number;
  display_id?: string;
  item_id: number;
  title?: string;
  repo_url: string;
  status: string;
  trigger: string;
  container_name?: string;
  workspace_path?: string;
  web_port?: number | null;
  web_url?: string;
  created_at: string;
  finished_at?: string;
  result?: string;
  report?: ReproReport | null;
  log_excerpt?: string;
  /** 所属能力条目的终态结论(/repro-runs 与 /repro/{id} 带回)。not_supported ⇒ 展示「无需复现」,
   *  覆盖任务行原始 failed/success —— 同一件事不能两页两种说法。 */
  item_repro_status?: string;
  item_repro_skip_reason?: string;
}

export interface ConversionRecord {
  id: string;
  capability_id: string;
  title: string;
  status: string;
  scenario: string;
  owner: string;
  next_action: string;
  notes: string;
}

export interface ClassifyStats {
  total: number;
  classified: number;
  unclassified: number;
  web_count: number;
}

export interface LibraryStats {
  domain: string;
  total: number;
  web: number;
  non_web: number;
  demo: number;
  repro: {
    success: number;
    partial: number;
    in_progress: number;
    pending: number;
    failed: number;
    not_supported: number;
  };
}

/** /api/capabilities/items 的响应。total 是命中总数(服务端精确计数), 供分页用。 */
export interface LibraryItemsResponse {
  domain: string;
  label: string;
  count: number;
  total: number;
  page: number | null;
  page_size: number | null;
  items: CapabilityItem[];
}

/** 形态筛选键(与后端 form 参数同名) */
export type LibraryFormKey = 'web' | 'non_web';

/** 可体验·复现筛选键: 与 /items/stats 的 repro 桶名、/items?repro= 参数三者同名 */
export type ReproBucketKey = 'demo' | 'success' | 'partial' | 'in_progress' | 'pending' | 'failed' | 'not_supported';


export interface CapStats {
  total: number;
  candidates: number;
  capabilities: number;
  conversions: number;
  repro_succeeded: number;
  repro_active: number;
}
