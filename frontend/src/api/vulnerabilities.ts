import { getJson, postJson } from './client';
import type {
  DomainItem,
  FieldReviewRequest,
  FieldReviewResponse,
  KnowledgePayload,
  KeywordProfile,
  ListResponse,
  MaterialPayload,
  PipelineRunDetail,
  PipelineRunSummary,
  PipelineRunStartResponse,
  ShadowEvaluationPayload,
  VulnerabilityTodayResponse,
  VulnerabilityRunResults,
} from '../types/vulnerability';

export function fetchVulnerabilityToday(): Promise<VulnerabilityTodayResponse> {
  return getJson('/api/vulnerabilities/today');
}

export function fetchVulnerabilityMaterials(): Promise<ListResponse<DomainItem<MaterialPayload>>> {
  return getJson('/api/vulnerabilities/materials?limit=200');
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

export function fetchVulnerabilityKeywordProfiles(): Promise<{ items: KeywordProfile[] }> {
  return getJson('/api/vulnerabilities/keyword-profiles');
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

export function fetchVulnerabilityExtractions(): Promise<ListResponse<DomainItem<KnowledgePayload>>> {
  return getJson('/api/vulnerabilities/extractions?limit=200');
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
  const response = await fetch(`/api/vulnerabilities/knowledge/${itemId}/fields/${encodeURIComponent(fieldName)}/${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`field review ${action}: ${response.status}`);
  return response.json() as Promise<FieldReviewResponse>;
}
