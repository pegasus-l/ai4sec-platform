export type NewsView = 'today' | 'all' | 'reports' | 'topics' | 'ops-overview' | 'ops-runs' | 'ops-sources' | 'ops-quality';
export type NewsType = 'paper' | 'project';

export interface NewsItem {
  id: number;
  item_type: NewsType;
  title: string;
  summary: string;
  highlight: string;
  source: string;
  source_url: string;
  primary_date: string;
  score: number;
  status: string;
  tags: string[];
  technical_points: string[];
  payload: Record<string, unknown>;
  user_state: { reading_state: string; feedback_value: string; feedback_reason: string };
  paper?: { arxiv_id: string; authors: string[]; abstract: string; code_url: string } | null;
  project?: { repo_full_name: string; stars: number; forks: number; language: string; updated_at: string; linked_paper_ids: number[] } | null;
}

export interface NewsListResponse {
  items: NewsItem[];
  page: number;
  page_size: number;
  total: number;
  filters: Record<string, unknown>;
}

export interface TodayResponse {
  date: string;
  kpis: Record<string, number>;
  highlights: NewsItem[];
  topic_summary: Array<{ topic: string; item_count: number; latest_at: string; items: number[] }>;
  source_summary: Array<{ id: string; name: string; count: number; status: string }>;
}

export interface Report {
  report_date: string;
  title: string;
  summary: string;
  highlights: number[];
  topic_sections: Array<{ topic: string; summary: string; item_ids: number[] }>;
  metrics: Record<string, number>;
  items?: NewsItem[];
}

export interface TopicSummary {
  topic: string;
  item_count: number;
  latest_at: string;
  items: number[];
}

export interface TechMapItem {
  dimension: string;
  category: string;
  point: string;
  count: number;
}

export interface TechMapResponse {
  name: string;
  version: string;
  items: TechMapItem[];
}
