import { getJson, postJson } from '../../api/client';
import type { NewsListResponse, NewsView, Report, TechMapResponse, TodayResponse, TopicSummary } from './newsTypes';

export interface NewsFilters {
  query: string;
  item_type: string;
  source: string;
  topic: string;
  tech_dimensions: string[];
  tech_categories: string[];
  tech_points: string[];
  tech_match: 'any' | 'all';
  status: string;
  sort: string;
  page: number;
}

export function newsUrl(view: NewsView, filters: NewsFilters): string {
  if (view === 'today') return '/api/news/today?limit=12';
  if (view === 'reports') return '/api/news/reports?limit=30';
  if (view === 'topics') return '/api/news/topics?limit=50';
  const params = new URLSearchParams({ page: String(filters.page), page_size: '24', sort: filters.sort });
  Object.entries(filters).forEach(([key, value]) => {
    if (key === 'page' || key === 'sort' || key.startsWith('tech_') || !value) return;
    params.set(key, String(value));
  });
  filters.tech_dimensions.forEach(value => params.append('tech_dimension', value));
  filters.tech_categories.forEach(value => params.append('tech_category', value));
  filters.tech_points.forEach(value => params.append('tech_point', value));
  if (filters.tech_dimensions.length + filters.tech_categories.length + filters.tech_points.length > 1) params.set('tech_match', filters.tech_match);
  return `/api/news/items?${params.toString()}`;
}

export type NewsResponse = TodayResponse | NewsListResponse | { items: Report[] } | { items: TopicSummary[] };

export function fetchNews(view: NewsView, filters: NewsFilters): Promise<NewsResponse> {
  return getJson<NewsResponse>(newsUrl(view, filters));
}

export function fetchReport(reportDate: string): Promise<Report> {
  return getJson<Report>(`/api/news/reports/${encodeURIComponent(reportDate)}`);
}

export function fetchTechMap(): Promise<TechMapResponse> {
  return getJson<TechMapResponse>('/api/news/tech-map');
}

export function postNewsAction(itemId: number, action: string): Promise<Record<string, unknown>> {
  return postJson(`/api/news/items/${itemId}/${action}`);
}

export function fetchNewsOps<T>(section: 'overview' | 'runs' | 'sources' | 'quality'): Promise<T> {
  return getJson<T>(`/api/news/ops/${section}`);
}

export function fetchNewsRun<T>(runId: string): Promise<T> {
  return getJson<T>(`/api/news/ops/runs/${encodeURIComponent(runId)}`);
}

export function startNewsPipeline(sources?: string[]): Promise<Record<string, unknown>> {
  return postJson('/api/runs', { pipeline_name: 'news.daily_pipeline', reset: false, params: sources?.length ? { sources } : {} });
}

export function retryNewsRun(runId: string): Promise<Record<string, unknown>> {
  return postJson(`/api/runs/${encodeURIComponent(runId)}/retry`, {});
}

export function retryNewsSource(source: string): Promise<Record<string, unknown>> {
  return postJson(`/api/news/ops/sources/${encodeURIComponent(source)}/retry`, {});
}

export function updateNewsReviewQueue(itemId: number, action: 'reject' | 'reopen'): Promise<Record<string, unknown>> {
  return postJson(`/api/news/ops/review-queue/${itemId}`, { action });
}
