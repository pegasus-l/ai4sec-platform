export const BASE = '/insights';  // ASIS 反代挂载路径

/** 入口网关(136 radar)的登录页; 与后端 SEC_AI_LOGIN_URL 保持同一取值。 */
export const LOGIN_PATH = '/login';

/** 401/403 时派发的全局事件: 由 AuthExpiredBanner 监听(见该组件注释)。 */
export const AUTH_REQUIRED_EVENT = 'ai4sec:auth-required';

/**
 * 横幅要显示的三种处境。区别很关键: 前两种登录一下就能解决, 第三种登录也没用。
 *   expired        401, 完全没有有效会话
 *   readonly_login 403 + reason=session_expired, 有嵌入票但没有本平台登录 ⇒ 掉线了
 *   readonly_account 403 + reason=insufficient_role, 登录有效但账号本身是只读
 */
export type AuthNoticeKind = 'expired' | 'readonly_login' | 'readonly_account';

/** 事件载荷。autoRedirect 决定横幅能不能替用户跳登录页(见 AuthExpiredBanner)。 */
export interface AuthNoticeDetail {
  kind: AuthNoticeKind;
  /** 这次失败来自用户主动点的写操作 ⇒ 允许自动跳登录页; 后台轮询永远不许。 */
  autoRedirect: boolean;
}

// 会话过期后页面上会有一串轮询(复现状态每 5s 一次)同时报错 —— 事件节流, 避免横幅反复重挂。
const AUTH_NOTICE_INTERVAL_MS = 5000;
let lastAuthNoticeAt = 0;

function notifyAuthRequired(kind: AuthNoticeKind, autoRedirect: boolean = false): void {
  const now = Date.now();
  // 后台轮询的报错要节流; 但用户主动写操作触发的这一次必须放行 —— 否则可能出现
  // "轮询刚把事件节流掉, 紧接着点按钮的 403 被丢弃", 自动跳转永远不触发。
  if (!autoRedirect && now - lastAuthNoticeAt < AUTH_NOTICE_INTERVAL_MS) return;
  lastAuthNoticeAt = now;
  const detail: AuthNoticeDetail = { kind, autoRedirect };
  window.dispatchEvent(new CustomEvent<AuthNoticeDetail>(AUTH_REQUIRED_EVENT, { detail }));
}

/**
 * 401/403 的统一处置。
 *
 * 2026-10-31: 以前只认 401。但会话过期时后端会静默回退到入口网关的嵌入票(viewer),
 * 写操作因此返回 403 而不是 401 —— 前端把它当成普通报错, 用户看到"点复现报 403 且
 * 怎么刷新都不跳登录页"。现在按后端给的 reason 区分, 让横幅说人话。
 *
 * autoRedirect 只由写请求传 true: 用户点了按钮才值得把人送到登录页; 后台轮询触发的
 * 过期(比如正开着复现日志页)只提示、不动页面。
 */
async function handleAuthFailure(response: Response, autoRedirect: boolean = false): Promise<void> {
  if (response.status === 401) {
    notifyAuthRequired('expired', autoRedirect);
    return;
  }
  if (response.status !== 403) return;
  try {
    const body = await response.clone().json();
    if (body?.reason === 'session_expired') notifyAuthRequired('readonly_login', autoRedirect);
    else if (body?.error === 'read_only_session') notifyAuthRequired('readonly_account');
  } catch {
    // 不是 JSON 的 403(来自别处)与登录态无关, 保持原样抛错
  }
}

/** 当前页面地址 → 登录页回跳链接(重新登录后回到用户原来看的那一页)。 */
export function loginUrl(): string {
  const next = window.location.pathname + window.location.search;
  return `${LOGIN_PATH}?next=${encodeURIComponent(next)}`;
}

export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(BASE + path, { cache: 'no-store' });
  if (!response.ok) {
    await handleAuthFailure(response);
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
    await handleAuthFailure(response, true);
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

/** PATCH 与 POST 同一套约定(401/403 派发横幅事件 / 非 2xx 抛错)。案例库的字段编辑用它。 */
export async function patchJson<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(BASE + path, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    cache: 'no-store',
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!response.ok) {
    await handleAuthFailure(response, true);
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export async function deleteJson<T>(path: string): Promise<T> {
  const response = await fetch(BASE + path, { method: 'DELETE', cache: 'no-store' });
  if (!response.ok) {
    await handleAuthFailure(response, true);
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

export async function fetchTargets(page: number = 1, perPage: number = 50, surface: string = '', grade: string = '', search: string = '', includeFiltered: boolean = false): Promise<{ items: Record<string, unknown>[]; total: number; page: number; per_page: number; pages: number; filtered_hidden: number }> {
  const params = new URLSearchParams({ page: String(page), per_page: String(perPage), fields: 'summary' });
  if (surface) params.set('surface', surface);
  if (grade) params.set('grade', grade);
  if (search) params.set('search', search);
  if (includeFiltered) params.set('include_filtered', 'true');
  return getJson(`/api/threats/targets?${params.toString()}`);
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
  /** 仓库链接(来自 domain_items.source_url),让关联页打开的抽屉副标题与代码仓页一致。 */
  url?: string;
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
