import { getJson, postJson } from '../../api/client';
import type { NewsListResponse, NewsView, Report, TodayResponse, TopicSummary } from './newsTypes';

export interface NewsFilters {
  query: string;
  item_type: string;
  source: string;
  topic: string;
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
    if (key !== 'page' && key !== 'sort' && value) params.set(key, value);
  });
  return `/api/news/items?${params.toString()}`;
}

export type NewsResponse = TodayResponse | NewsListResponse | { items: Report[] } | { items: TopicSummary[] };

export function fetchNews(view: NewsView, filters: NewsFilters): Promise<NewsResponse> {
  return getJson<NewsResponse>(newsUrl(view, filters));
}

export function fetchReport(reportDate: string): Promise<Report> {
  return getJson<Report>(`/api/news/reports/${encodeURIComponent(reportDate)}`);
}

export function postNewsAction(itemId: number, action: string): Promise<Record<string, unknown>> {
  return postJson(`/api/news/items/${itemId}/${action}`);
}
