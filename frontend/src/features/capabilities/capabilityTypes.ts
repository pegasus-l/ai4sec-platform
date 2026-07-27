export type CapabilityView = 'today' | 'library' | 'repro' | 'conversion' | 'ops-overview' | 'ops-quality' | 'ops-runs';

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
    code_url?: string;
    source_type?: string;
    capability_type?: string;
    sub_type?: string;
    application_scenarios?: string[];
    tech_points?: string[];
    repro_status?: string;
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
    one_liner?: string;
    usage?: Record<string, string>;
    blockers?: string[];
    gotchas?: string[];
    source_news_item?: Record<string, unknown>;
  };
  metrics?: Record<string, unknown>;
}

export interface ReproReport {
  level?: string;
  status: string;
  summary: string;
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
}

export interface ReproTask {
  id: number;
  item_id: number;
  repo_url: string;
  status: string;
  trigger: string;
  web_port?: number | null;
  web_url?: string;
  created_at: string;
  finished_at?: string;
  result?: string;
  report?: ReproReport | null;
  log_excerpt?: string;
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

export interface CapStats {
  total: number;
  candidates: number;
  capabilities: number;
  conversions: number;
  repro_succeeded: number;
  repro_active: number;
}
