import { BASE, deleteJson, getJson, patchJson, postJson } from './client';
import type {
  CaseDetail,
  CaseListResponse,
  CaseSourceTarget,
  CaseStats,
  ComprehensionProbePayload,
  ComprehensionSummary,
  DomainItem,
  FieldReviewRequest,
  FieldReviewResponse,
  KnowledgePayload,
  KeywordCategory,
  KeywordProfile,
  ListResponse,
  ManualKeyword,
  ManualKeywordListResponse,
  MaterialPayload,
  PagedListResponse,
  PatternPayload,
  PipelineRunDetail,
  Project,
  ProjectDetectResult,
  ProjectLinkResult,
  ProjectListResponse,
  ProjectPayload,
  ProjectPackage,
  PipelineRunSummary,
  PipelineRunStartResponse,
  ShadowEvaluationPayload,
  VulnerabilityTodayResponse,
  VulnerabilityRunResults,
} from '../types/vulnerability';

export function fetchVulnerabilityToday(): Promise<VulnerabilityTodayResponse> {
  return getJson('/api/vulnerabilities/today?limit=200');
}

export interface MaterialListParams {
  q?: string;
  chip?: string | null;
  sort?: 'score' | 'recent';
  page?: number;
  page_size?: number;
}

/**
 * 素材列表(服务端分页)。chip/sort/q/page 都下推给服务端。
 * 响应里 total = 命中总数(精确), chip_counts = 全量芯片计数(不受 q/chip 影响)。
 * 2026-09-17 之前是写死的 `?limit=200` —— 库里可展示素材已经 300+ 条, 分数最低的那批在页面上
 * 永远不可达, 而页面上又看不出"还有更多"。
 */
export function fetchVulnerabilityMaterials(
  params: MaterialListParams = {},
): Promise<PagedListResponse<DomainItem<MaterialPayload>>> {
  const sp = new URLSearchParams();
  if (params.q) sp.set('q', params.q);
  if (params.chip && params.chip !== 'all') sp.set('chip', params.chip);
  if (params.sort) sp.set('sort', params.sort);
  if (params.page) sp.set('page', String(params.page));
  if (params.page_size) sp.set('page_size', String(params.page_size));
  const qs = sp.toString();
  return getJson(`/api/vulnerabilities/materials${qs ? `?${qs}` : ''}`);
}

/** 单条素材一键下载地址：<a href> 直接跳转，服务器按 Content-Disposition 触发下载。 */
export function materialDownloadUrl(itemId: number): string {
  return `${BASE}/api/vulnerabilities/materials/${itemId}/download`;
}

/**
 * 批量下载：POST 打包 zip 后通过临时 <a> 保存为文件。返回是否成功。
 *
 * 服务端分页后前端手里只有当前页 20 条, 所以改为把**筛选条件**发过去, 由服务端按同一套谓词
 * 取"命中的全部" —— 否则这个按钮会静默退化成"只下载当前页", 而 zip 里少了哪些文件是看不出来的。
 * item_ids 仍保留(按 id 精确打包), 但页面不再用那条路径。
 */
export async function downloadMaterialZip(
  params: { item_ids?: number[]; q?: string; chip?: string | null },
): Promise<boolean> {
  const response = await fetch(`${BASE}/api/vulnerabilities/materials/bulk-download`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      item_ids: params.item_ids,
      q: params.q || null,
      chip: params.chip && params.chip !== 'all' ? params.chip : null,
    }),
  });
  if (!response.ok) return false;
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = 'vuln_materials_bulk.zip';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(objectUrl);
  return true;
}

export function fetchVulnerabilityCandidates(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/candidates?limit=200');
}

export function fetchVulnerabilityCrawledPages(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/crawled-pages?limit=200');
}

export function fetchVulnerabilityExtractedContent(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/extracted-content?limit=200');
}

export function fetchVulnerabilityMaterialReviews(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/material-reviews?limit=200');
}

export function fetchVulnerabilityEvaluations(): Promise<ListResponse<DomainItem<ShadowEvaluationPayload>>> {
  return getJson('/api/vulnerabilities/evaluations?limit=20');
}

export function fetchVulnerabilityKeywordProfiles(): Promise<{ items: KeywordProfile[]; max_manual_queries?: number; wildcard_manual_queries?: number }> {
  return getJson('/api/vulnerabilities/keyword-profiles');
}

/** 词表里 18 个漏洞大类的全部关键词(2026-10-15 新增端点)。 */
export function fetchKeywordCategories(): Promise<{ items: KeywordCategory[] }> {
  return getJson('/api/vulnerabilities/keyword-categories');
}

// ============================================================================
// 人工检索关键词 (GET/POST/DELETE /api/vulnerabilities/manual-keywords)
// ============================================================================

export function fetchManualKeywords(profile = ''): Promise<ManualKeywordListResponse> {
  const query = profile ? `?profile=${encodeURIComponent(profile)}` : '';
  return getJson(`/api/vulnerabilities/manual-keywords${query}`);
}

export function addManualKeyword(input: { profile_name: string; keyword: string; label?: string; note?: string }): Promise<{ keyword: ManualKeyword; created: boolean; existing_scope?: string }> {
  // existing_scope 只在"这个词已挂在**另一个**范围下"时回带 —— 后端不再插重复行,
  // 前端据此告诉用户它现在挂在哪(否则用户会以为没生效)。
  return postJson('/api/vulnerabilities/manual-keywords', input);
}

export function setManualKeywordEnabled(id: number, enabled: boolean): Promise<{ keyword: ManualKeyword }> {
  // 不带 body —— 后端按 /enable 或 /disable 两个路径区分(与 ops 的采集目标同一约定)。
  return postJson(`/api/vulnerabilities/manual-keywords/${id}/${enabled ? 'enable' : 'disable'}`);
}

export function deleteManualKeyword(id: number): Promise<{ status: string; id: number }> {
  return deleteJson(`/api/vulnerabilities/manual-keywords/${id}`);
}

// ============================================================================
// 人工投喂素材 (POST /api/vulnerabilities/materials/manual)
// ============================================================================

/**
 * 投喂一篇漏洞文章。**异步**:后端立刻返回 run_id,抓取/抽取/评审在后台跑(30s 起)。
 * 拿 run_id 去轮询现成的进度组件即可;投喂的素材强制入库(模型判 reject 也进,
 * 模型结论保留为元数据),正文短于 200 字会被后端 400 拒绝。
 */
export function ingestManualMaterial(input: { url: string; title?: string; body?: string; note?: string }): Promise<PipelineRunStartResponse> {
  return postJson('/api/vulnerabilities/materials/manual', input);
}

export function runVulnerabilityDiscovery(input: { keywordProfile: string; maxQueries: number; maxResults: number; crawlLimit: number; queryBatchSize: number; timeRangeMode: string; recentDays: number; startDate: string; endDate: string }): Promise<PipelineRunStartResponse> {
  return postJson('/api/runs', {
    pipeline_name: 'vulnerabilities.batched_full_knowledge_discovery_pipeline',
    reset: false,
    wait: false,
    params: {
      keyword_profile: input.keywordProfile,
      max_queries: input.maxQueries,
      max_results: input.maxResults,
      crawl_limit: input.crawlLimit,
      query_batch_size: input.queryBatchSize,
      time_range_mode: input.timeRangeMode,
      recent_days: input.recentDays,
      start_date: input.startDate,
      end_date: input.endDate,
      allow_large_keyword_profile: true,
      max_run_queries: input.maxQueries,
      resume: true,
      domain: 'security',
      zone: 'cn',
      language: 'zh-CN',
    },
  });
}

export function retryVulnerabilityCrawlFailures(items: DomainItem[]): Promise<PipelineRunStartResponse> {
  return postJson('/api/runs', {
    pipeline_name: 'vulnerabilities.full_knowledge_discovery_pipeline',
    reset: false,
    wait: false,
    params: {
      seed_candidates: items.map(item => ({
        title: item.title,
        url: item.source_url,
        snippet: item.summary,
        search_keyword: String(item.payload?.search_keyword ?? 'crawl_failure_retry'),
      })),
      prefer_url_fetch: true,
      crawl_limit: items.length,
      max_results: items.length,
      crawl_max_retries: 2,
    },
  });
}

export function fetchVulnerabilityRunResults(runId: string): Promise<VulnerabilityRunResults> {
  return getJson(`/api/vulnerabilities/runs/${encodeURIComponent(runId)}/results`);
}

export function fetchPipelineRun(runId: string): Promise<PipelineRunDetail> {
  return getJson(`/api/runs/${encodeURIComponent(runId)}`);
}

export function fetchVulnerabilityRuns(): Promise<{ items: PipelineRunSummary[] }> {
  return getJson('/api/vulnerabilities/runs?limit=30');
}

export function fetchVulnerabilityEvents(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/events?limit=200');
}

export function fetchVulnerabilityEventDetail(itemId: number): Promise<DomainItem & { materials?: DomainItem<MaterialPayload>[] }> {
  return getJson(`/api/vulnerabilities/events/${itemId}`);
}

// ============================================================================
// 漏洞案例库 (2026-10-16): 一个洞一行, 取代原来"从素材聚合出的主题"事件
// ============================================================================

export interface CaseListParams {
  q?: string;
  severity?: string;
  id_kind?: string;
  source?: string;
  status?: string;
  /** full(4 位全有) / partial(有上下文但没齐) / empty(只有元数据) */
  completeness?: string;
  /** 只看某个项目的洞(P5a);由项目视图传下来 */
  project_id?: number;
  /** true = 只看 B 层(有 OSV/补丁/CVSS≥9/人工/项目命中的洞);不传 = 全量索引 */
  curated?: boolean;
  published_from?: string;
  published_to?: string;
  limit?: number;
  offset?: number;
}

/**
 * 案例列表。**关键词与所有筛选都下推 SQL 分页** —— 库是 15.5GB 量级, 拉全量回前端筛就是
 * 素材库当年"分数最低那批永远不可达"的翻版。offset 分页(不是页码)。
 */
export function fetchCases(params: CaseListParams = {}): Promise<CaseListResponse> {
  const sp = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '') sp.set(key, String(value));
  });
  const qs = sp.toString();
  return getJson(`/api/vulnerabilities/cases${qs ? `?${qs}` : ''}`);
}

export function fetchCaseStats(): Promise<CaseStats> {
  return getJson('/api/vulnerabilities/cases/stats');
}

/**
 * 按 id 取单条素材。案例抽屉的「关联素材」只带 id/标题/链接三件套(案例里不抄素材正文),
 * 点进去要拿完整素材才能复用现成的素材抽屉 —— 这是那条路径的唯一入口。
 */
export function fetchVulnerabilityMaterial(itemId: number): Promise<DomainItem<MaterialPayload>> {
  return getJson(`/api/vulnerabilities/materials/${itemId}`);
}

export function fetchCaseDetail(caseId: number): Promise<CaseDetail> {
  return getJson(`/api/vulnerabilities/cases/${caseId}`);
}

/**
 * 人工添加一个洞。
 *   mode='auto'   贴 CVE/GHSA/OSV id → 落 status='pending_fetch', 采集步(自动或手动触发)去抓元数据
 *   mode='manual' 完全手填(没有外部 id 的项目内部 bug) → 主键由标题+链接派生, 直接 active
 * 重复添加是同一条(不插新行): auto 按 canonical_id 幂等, manual 按派生主键幂等。
 */
export function addCase(input: { mode: 'auto' | 'manual'; canonical_id?: string; title?: string; summary?: string; severity?: string; cvss_score?: number | null; source_url?: string; cwe_ids?: string[]; affected_products?: string[]; references?: string[]; code?: string; note?: string }): Promise<{ case_id: number; canonical_id: string; created: boolean; context_inserted: number }> {
  return postJson('/api/vulnerabilities/cases', input);
}

export function updateCase(caseId: number, fields: Record<string, unknown>): Promise<{ case_id: number; changed: number }> {
  return patchJson(`/api/vulnerabilities/cases/${caseId}`, fields);
}

/** 人工补一条上下文。provenance 由后端固定成 manual_added(这个入口不接受来源标注)。 */
export function addCaseContext(caseId: number, row: { context_type: string; content?: string; confidence?: number; repo?: string; commit_sha?: string; file_path?: string; function_name?: string; start_line?: number; end_line?: number; source_url?: string; label?: string }): Promise<{ case_id: number; inserted: number }> {
  return postJson(`/api/vulnerabilities/cases/${caseId}/context`, row);
}

export function fetchCaseSources(): Promise<{ count: number; items: CaseSourceTarget[] }> {
  return getJson('/api/vulnerabilities/case-sources');
}

export function addCaseSource(input: { kind: string; identifier: string; source_key?: string; label?: string; note?: string }): Promise<{ source: CaseSourceTarget; created: boolean }> {
  return postJson('/api/vulnerabilities/case-sources', input);
}

/** 不带 body, 用两个路径区分开关(与人工关键词同一约定) */
export function setCaseSourceEnabled(sourceId: number, enabled: boolean): Promise<CaseSourceTarget> {
  return postJson(`/api/vulnerabilities/case-sources/${sourceId}/${enabled ? 'enable' : 'disable'}`);
}

export function deleteCaseSource(sourceId: number): Promise<{ deleted: number }> {
  return deleteJson(`/api/vulnerabilities/case-sources/${sourceId}`);
}

// ── 项目(P5a)────────────────────────────────────────────────────────────────

export function fetchProjects(includeDisabled = true): Promise<ProjectListResponse> {
  return getJson(`/api/vulnerabilities/projects?include_disabled=${includeDisabled ? 'true' : 'false'}`);
}

/** 新增项目。后端建完会立即做一次全量关联, 所以返回值里带 link 统计。 */
export function addProject(input: ProjectPayload): Promise<{ project: Project; created: boolean; link: ProjectLinkResult }> {
  return postJson('/api/vulnerabilities/projects', input);
}

export function updateProject(
  projectId: number,
  fields: { display_name?: string; packages?: Array<string | ProjectPackage>; tier?: string; native_sources?: string[] },
): Promise<{ project: Project; changed: number; link?: ProjectLinkResult }> {
  return patchJson(`/api/vulnerabilities/projects/${projectId}`, fields);
}

/** 不带 body, 用两个路径区分开关(与盯源/人工关键词同一约定) */
export function setProjectEnabled(projectId: number, enabled: boolean): Promise<Project> {
  return postJson(`/api/vulnerabilities/projects/${projectId}/${enabled ? 'enable' : 'disable'}`);
}

/** 手动重扫关联。since 传 ISO 时间只扫最近更新的案例; 不传 = 全量(幂等)。 */
export function linkProjectCases(projectId: number, since = ''): Promise<ProjectLinkResult> {
  const qs = since ? `?since=${encodeURIComponent(since)}` : '';
  return postJson(`/api/vulnerabilities/projects/${projectId}/link${qs}`);
}

export function deleteProject(projectId: number): Promise<{ deleted: number }> {
  return deleteJson(`/api/vulnerabilities/projects/${projectId}`);
}

/** 读仓库根目录 manifest 猜发布包。**只回候选**, 不落库。 */
export function detectProjectPackages(url: string): Promise<ProjectDetectResult> {
  return postJson('/api/vulnerabilities/projects/detect', { url });
}

export function fetchProjectCases(projectId: number, limit = 50, offset = 0): Promise<CaseListResponse> {
  return getJson(`/api/vulnerabilities/projects/${projectId}/cases?limit=${limit}&offset=${offset}`);
}

/**
 * 手动触发一个项目的自有源同步(P5b)。走 /api/runs 的**后台跑批**,不在请求里等结果:
 * 一次同步要逐条去 NVD/OSV 核实编号(未鉴权 NVD 5 次/30 秒),几秒到几分钟都有可能;
 * 而且 04:00 的主链路可能还占着全局锁 —— 排队比长时间挂着一个 HTTP 请求诚实。
 */
export function runProjectNativeSync(projectId: number): Promise<PipelineRunStartResponse> {
  return postJson('/api/runs', {
    pipeline_name: 'vulnerabilities.project_buglist_pipeline',
    reset: false,
    wait: false,
    params: { project_ids: [projectId] },
  });
}

export function fetchVulnerabilityExtractions(): Promise<ListResponse<DomainItem<KnowledgePayload>>> {
  return getJson('/api/vulnerabilities/extractions?limit=200');
}

export function fetchVulnerabilityPatterns(): Promise<ListResponse<DomainItem<PatternPayload>>> {
  return getJson('/api/vulnerabilities/patterns?limit=200');
}

/** 漏洞模式 markdown 下载地址：<a href> 直接跳转，服务器按 Content-Disposition 触发下载。 */
export function patternDownloadUrl(itemId: number): string {
  return `${BASE}/api/vulnerabilities/patterns/${itemId}/download`;
}

/**
 * 单条知识喂给模型的知识片段原文(JSON)。
 * 「漏洞知识库」「抽取审核」两个页面 2026-10-16 已撤, 这个接口是撤页后**仍然免费**的
 * 抽取质量检查途径 —— 出问题时看得到原始片段, 不必为排查把页面加回来。
 */
export function knowledgeSnippetUrl(itemId: number): string {
  return `${BASE}/api/vulnerabilities/knowledge/${itemId}/model-snippet`;
}

/** 触发漏洞模式抽象 pipeline(按 CWE 聚类已确认知识, 跨素材归纳模式)。 */
export function runPatternSynthesis(): Promise<PipelineRunStartResponse> {
  return postJson('/api/runs', {
    pipeline_name: 'vulnerabilities.pattern_synthesis_pipeline',
    reset: false,
    wait: false,
    params: {},
  });
}

export function fetchVulnerabilityComprehension(): Promise<ListResponse<DomainItem<ComprehensionProbePayload>>> {
  return getJson('/api/vulnerabilities/comprehension?limit=200');
}

export function fetchComprehensionSummary(): Promise<ComprehensionSummary> {
  return getJson('/api/vulnerabilities/comprehension/summary');
}

/** 可理解性验证 markdown 下载地址：<a href> 直接跳转，服务器按 Content-Disposition 触发下载。 */
export function probeDownloadUrl(itemId: number): string {
  return `${BASE}/api/vulnerabilities/comprehension/${itemId}/download`;
}

/** 触发可理解性验证 pipeline(新 LLM 读素材作答 + judge 对拍打分)。 */
export function runComprehensionProbe(): Promise<PipelineRunStartResponse> {
  return postJson('/api/runs', {
    pipeline_name: 'vulnerabilities.comprehension_probe_pipeline',
    reset: false,
    wait: false,
    params: {},
  });
}

export function fetchVulnerabilityKnowledge(): Promise<ListResponse<DomainItem<KnowledgePayload>>> {
  return getJson('/api/vulnerabilities/extractions?limit=200');
}

export async function acceptKnowledgeField(itemId: number, fieldName: string, body: FieldReviewRequest): Promise<FieldReviewResponse> {
  return postFieldReview(itemId, fieldName, 'accept', body);
}

export async function modifyKnowledgeField(itemId: number, fieldName: string, body: FieldReviewRequest): Promise<FieldReviewResponse> {
  return postFieldReview(itemId, fieldName, 'modify', body);
}

export async function rejectKnowledgeField(itemId: number, fieldName: string, body: FieldReviewRequest): Promise<FieldReviewResponse> {
  return postFieldReview(itemId, fieldName, 'reject', body);
}

async function postFieldReview(itemId: number, fieldName: string, action: 'accept' | 'modify' | 'reject', body: FieldReviewRequest): Promise<FieldReviewResponse> {
  const response = await fetch(`/insights/api/vulnerabilities/knowledge/${itemId}/fields/${encodeURIComponent(fieldName)}/${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`field review ${action}: ${response.status}`);
  return response.json() as Promise<FieldReviewResponse>;
}
