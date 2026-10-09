import { getJson, postJson, deleteJson } from './client';

export interface OpsOverviewData {
  db_stats: { repos: number; assets: number; today: number; queue: number; cve_unique: number; pipeline_runs: number; evidence_items: number; quality_audits: number };
  last_run: { run_id: string; pipeline: string; status: string; started_at: string; finished_at: string; days_ago: number | null } | null;
  ai_stats: { ai_reviews: number; asset_associations: number; model_calls: number };
  ai_reviews: Array<{ item_id: number; title: string; score: number; summary: string; calibrated_surface: string; confidence: number }>;
  ai_associations: Array<{ item_id: number; title: string; source: string; association_count: number; summary: string; associations: unknown[] }>;
}

/** 一个采集目标(组织 / hub id / 站点),内置或人工添加。 */
export interface OpsSourceTarget {
  id: number | null;
  source_key: string;
  target_type: string;
  /** 组织名 / hub_id / 站点 URL,采集时真正用的标识。 */
  identifier: string;
  label: string;
  enabled: boolean;
  /** 人工添加者(取自入口网关会话;为空表示内置目标,代码里带的)。 */
  created_by: string;
  created_at: string;
  /** true = 代码里内置(不可删,只能停用);false = 人工添加。 */
  builtin: boolean;
}

/** 一个数据源(具体到网站/接口),页面主体就是它。 */
export interface OpsSourceGroup {
  key: string;
  name: string;
  /** repo / asset / vuln / material */
  kind: string;
  /** 具体站点,如 gitcode.com、atomgit.com、hiascend.com。 */
  site: string;
  entry_url: string;
  collector: string;
  note: string;
  targets: OpsSourceTarget[];
  records: number;
  last_sync: string;
  days_ago: number | null;
  /** ok=今日有采集 / stale=超过 2 天 / never=从未采集 / pending=人工登记待接入 */
  status: 'ok' | 'stale' | 'never' | 'pending';
  builtin: boolean;
}

export interface OpsSourcesData {
  groups: OpsSourceGroup[];
  /** 人工登记但还没有对应采集器的新站点(需要开发接入)。 */
  pending_sources: OpsSourceTarget[];
  total_records: number;
  /** 可添加采集目标的既有数据源 key(下拉选项)。 */
  addable_keys: Array<{ key: string; name: string; target_type: string; hint: string }>;
}

export interface OpsAISummaryData {
  ai_reviews: { count: number; items: Array<{ item_id: number; title: string; score: number; url: string; summary: string; calibrated_surface: string; rule_score_assessment: string; hypotheses: string[]; confidence: number; cve_priority: unknown[] }> };
  asset_associations: { count: number; items: Array<{ item_id: number; title: string; source: string; summary: string; associations: unknown[]; reviewed_at: string }> };
}

export interface OpsPipeline {
  name: string;
  short_name: string;
  description: string;
  risk: string;
  estimated_time: string;
  steps?: string;
  domain?: string;
}

export interface OpsRun {
  run_id: string;
  pipeline_name: string;
  status: string;
  started_at: string;
  finished_at: string;
  tasks?: Array<Record<string, unknown>>;
  artifacts?: Array<Record<string, unknown>>;
}

// Map step_name (in task_runs) → pipeline_name (in sub-step table)
export const STEP_TO_PIPELINE: Record<string, string> = {
  'collect_huawei_sources': 'threats.huawei_collect_sources_pipeline',
  'huawei_cve_scout': 'threats.huawei_cve_scout_pipeline',
  'huawei_attack_surface_score': 'threats.huawei_attack_surface_pipeline',
  'import_huawei_threat_assets': 'threats.huawei_asset_pipeline',
  'reason_threat_risk': 'threats.risk_reasoning_pipeline',
  'select_threat_risk_candidates': 'threats.risk_reasoning_pipeline',
};

export async function fetchRunDetail(runId: string): Promise<OpsRun> {
  return getJson(`/api/runs/${runId}`);
}

export async function fetchOpsOverview(): Promise<OpsOverviewData> {
  return getJson('/api/ops/overview');
}

export async function fetchOpsSources(): Promise<OpsSourcesData> {
  return getJson('/api/ops/sources');
}

/** 人工添加采集目标(仓库组织 / hub id)。立即生效:下一轮采集就会带上。 */
export async function addSourceTarget(input: { source_key: string; identifier: string; label?: string; target_type?: string }): Promise<{ status: string; target: OpsSourceTarget }> {
  return postJson('/api/ops/sources/targets', input);
}

/** 人工登记一个全新数据源(站点)。落库为待接入,需要开发采集器后才会有数据。 */
export async function addSourceSite(input: { site_url: string; label: string; note?: string }): Promise<{ status: string; source: OpsSourceTarget }> {
  return postJson('/api/ops/sources/sites', input);
}

export async function setSourceTargetEnabled(id: number, enabled: boolean): Promise<{ status: string; id: number; enabled: boolean }> {
  return postJson(`/api/ops/sources/targets/${id}/${enabled ? 'enable' : 'disable'}`);
}

export async function deleteSourceTarget(id: number): Promise<{ status: string; id: number }> {
  return deleteJson(`/api/ops/sources/targets/${id}`);
}

export async function fetchOpsAISummary(): Promise<OpsAISummaryData> {
  return getJson('/api/ops/ai-summary');
}

export async function fetchOpsPipelines(): Promise<{ items: OpsPipeline[] }> {
  return getJson('/api/ops/pipelines');
}

export async function fetchRuns(): Promise<{ items: OpsRun[] }> {
  return getJson('/api/runs');
}
