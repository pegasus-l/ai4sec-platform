import { getJson } from './client';

export interface OpsOverviewData {
  db_stats: { repos: number; assets: number; today: number; queue: number; cve_unique: number; pipeline_runs: number; evidence_items: number; quality_audits: number };
  last_run: { run_id: string; pipeline: string; status: string; started_at: string; finished_at: string; days_ago: number | null } | null;
  ai_stats: { ai_reviews: number; asset_associations: number; model_calls: number };
  ai_reviews: Array<{ item_id: number; title: string; score: number; summary: string; calibrated_surface: string; confidence: number }>;
  ai_associations: Array<{ item_id: number; title: string; source: string; association_count: number; summary: string; associations: unknown[] }>;
}

export interface OpsSourceItem {
  source: string;
  records: number;
  last_sync: string;
  days_ago: number | null;
  total_items: number;
}

export interface OpsQualityItem {
  id: number;
  domain: string;
  audit_type: string;
  status: string;
  score: number;
  summary: string;
  details: Record<string, unknown>;
  created_at: string;
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

export async function fetchOpsOverview(): Promise<OpsOverviewData> {
  return getJson('/api/ops/overview');
}

export async function fetchOpsSources(): Promise<{ items: OpsSourceItem[] }> {
  return getJson('/api/ops/sources');
}

export async function fetchOpsQuality(): Promise<{ items: OpsQualityItem[]; kpis: { total: number; passed: number; warned: number; failed: number } }> {
  return getJson('/api/ops/quality');
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
