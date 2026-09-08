export const BASE = '/insights';  // ASIS 反代挂载路径

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(BASE + path, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    cache: 'no-store',
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export async function fetchAssets(): Promise<{ items: Record<string, unknown>[]; count: number }> {
  return getJson('/api/threats/assets?limit=9999');
}

export async function fetchToday(): Promise<{ items: Record<string, unknown>[] }> {
  return getJson('/api/threats/today?limit=30');
}

export async function fetchTargets(page: number = 1, perPage: number = 50, surface: string = '', grade: string = '', search: string = ''): Promise<{ items: Record<string, unknown>[]; total: number; page: number; per_page: number; pages: number }> {
  const params = new URLSearchParams({ page: String(page), per_page: String(perPage), fields: 'summary' });
  if (surface) params.set('surface', surface);
  if (grade) params.set('grade', grade);
  if (search) params.set('search', search);
  return getJson(`/api/threats/targets?${params.toString()}`);
}

export async function fetchTrackingQueue(): Promise<{ items: Record<string, unknown>[] }> {
  return getJson('/api/threats/tracking-queue');
}

export async function trackTarget(itemId: string | number, priority: string = 'P1', reason: string = ''): Promise<{ status: string; title: string }> {
  return postJson(`/api/threats/targets/${itemId}/track`, { priority, reason });
}

export async function trackAsset(itemId: string | number, priority: string = 'P1', reason: string = ''): Promise<{ status: string; title: string }> {
  return postJson(`/api/threats/assets/${itemId}/track`, { priority, reason });
}

export async function fetchTargetDetail(itemId: string | number): Promise<Record<string, unknown>> {
  return getJson(`/api/threats/targets/${itemId}`);
}

export async function fetchGraph(): Promise<{ nodes: unknown[]; edges: unknown[] }> {
  return getJson('/api/threats/graph');
}

export interface SurfaceStats {
  total_repos: number;
  total_cves: number;
  total_sec: number;
  per_surface: Record<string, { count: number; cves: number; sec: number }>;
}

export async function fetchSurfaceStats(): Promise<SurfaceStats> {
  return getJson('/api/threats/surface-stats');
}

export interface AiAssociationResult {
  item_id: number;
  status: 'success' | 'cached';
  associations: {
    associations: Array<{ repo_id: string; repo_name: string; confidence: string; reason: string }>;
    summary: string;
    reviewed_at: string;
  };
}

export interface AiReviewResult {
  item_id: number;
  status: 'success' | 'cached';
  assessment: {
    summary: string;
    risk_score: number;
    risk_grade: string;
    semantic_review?: {
      summary: string;
      attack_surface_calibration: string;
      rule_score_assessment: string;
      cve_priority: Array<{ cve_id: string; value: string; reason: string }>;
      false_positives: string[];
      hypotheses: string[];
      confidence: number;
    };
    recommended_actions: string[];
  };
}

// ============================================================================
// 资产↔仓关联 bundle (GET /api/threats/associations)
// ============================================================================

export interface AssocRepoMeta {
  id: number;
  org: string;
  name: string;
  grade: string;
  cve: number;
  risk: number | null;
}

export interface AssocAssetMeta {
  id: number;
  title: string;
  source: string;
  cat: string;
  risk_in: number;
}

export interface AssocLink {
  id: number;
  conf: 'direct' | 'inferred' | 'weak';
  rel_type: string;
  method: string;
  reason: string;
  repo: AssocRepoMeta;
  asset: AssocAssetMeta;
}

/** orphan / not_run 侧栏条目(无独立来源字段,只带 title+cat)。 */
export interface AssocSideEntry {
  id: number;
  title: string;
  cat: string;
}

export interface AssocBundle {
  meta: {
    total_assets: number;
    linked_assets: number;
    orphan_assets: number;
    not_run_assets: number;
    total_links: number;
    by_confidence: { direct: number; inferred: number; weak: number };
  };
  links: AssocLink[];
  orphans: AssocSideEntry[];
  not_run: AssocSideEntry[];
}

export async function fetchAssociations(): Promise<AssocBundle> {
  return getJson('/api/threats/associations');
}

// ============================================================================
// 资产关联批跑 (POST/GET /api/runs) —— pipeline_name = threats.asset_association_pipeline
// ============================================================================

export type AssocRunScope = 'sample' | 'all';

export interface StartAssociationRunParams {
  scope?: AssocRunScope;
  sample_size?: number;
  asset_ids?: number[];
  force?: boolean;
}

export interface RunStarted {
  run_id: string;
  status: string;
  pipeline_name: string;
  poll_url: string;
}

export interface RunDetail {
  run_id: string;
  pipeline_name: string;
  domain?: string;
  status: string;
  started_at?: string;
  finished_at?: string;
  summary?: Record<string, unknown>;
  error_message?: string;
  tasks: Record<string, unknown>[];
  artifacts: Record<string, unknown>[];
  progress: {
    completed_steps: number;
    total_steps: number;
    current_step: string;
    item_progress?: { step?: string; completed?: number; total?: number; linked?: number; orphan?: number; failed?: number } | Record<string, unknown> | null;
  };
}

export const ASSOCIATION_PIPELINE = 'threats.asset_association_pipeline';

export async function startAssociationRun(params: StartAssociationRunParams = {}): Promise<RunStarted> {
  return postJson('/api/runs', { pipeline_name: ASSOCIATION_PIPELINE, reset: false, wait: false, params });
}

export async function fetchRun(runId: string): Promise<RunDetail> {
  return getJson(`/api/runs/${runId}`);
}

export async function fetchRunningAssociationRuns(): Promise<RunDetail[]> {
  const { items } = await getJson<{ items: RunDetail[] }>('/api/runs');
  return (items ?? []).filter(r => r.pipeline_name === ASSOCIATION_PIPELINE && r.status === 'running');
}

const RUN_TERMINAL = new Set(['success', 'failed', 'interrupted', 'cancelled']);

export function isRunTerminal(status: string | undefined): boolean {
  return Boolean(status && RUN_TERMINAL.has(status));
}
