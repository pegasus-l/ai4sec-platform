export type Grade = '严重' | '高' | '中' | '低' | 'A' | 'B' | 'C' | 'D' | string;

export interface ThreatRepo {
  id: string;
  title: string;
  org: string;
  name: string;
  url: string;
  summary: string;
  score: number;
  grade: Grade;
  status: string;
  surface: string;
  stars: number;
  cve: number;
  sa: number;
  sec: number;
  filtered: boolean;
  filteredReason?: string;
  breakdown: Record<string, number>;
  reasons: string[];
  evidence: string[];
  assets: string[];
  riskAssessment?: Record<string, unknown>;
  raw: Record<string, unknown>;
}

export interface ThreatAsset {
  id: string;
  title: string;
  source: string;
  sourceType: string;
  category: string;
  url: string;
  summary: string;
  score: number;
  status: string;
  tags: string[];
  raw: Record<string, unknown>;
}

export interface ThreatSummary {
  totalRepos: number;
  highRisk: number;
  withCve: number;
  totalCve: number;
  uniqueCve: number;
  totalSa: number;
  broadSecurity: number;
  assets: number;
  grades: Record<string, number>;
  scanModes: Record<string, number>;
  sourceStats: Record<string, number>;
}

export interface ThreatGraphNode {
  id: string;
  label: string;
  type: 'repo' | 'asset' | 'surface' | 'org' | 'cve';
  score?: number;
  meta?: Record<string, unknown>;
}

export interface ThreatGraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

export interface ThreatViewModel {
  summary: ThreatSummary;
  repos: ThreatRepo[];
  today: ThreatRepo[];
  assets: ThreatAsset[];
  queue: Array<Record<string, unknown>>;
  cveScout: Record<string, unknown>;
  attackSurface: Record<string, unknown>;
  reports: Record<string, unknown>;
  graph: { nodes: ThreatGraphNode[]; edges: ThreatGraphEdge[] };
}
