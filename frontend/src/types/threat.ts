import type { Node, Edge } from 'reactflow';

export type Grade = '严重' | '高' | '中' | '低' | 'A' | 'B' | 'C' | 'D' | string;

// ============================================================================
// ThreatRepo (unchanged)
// ============================================================================
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
  coordinationCve?: number;
  coordinationProjects?: string[];
  sa: number;
  sec: number;
  filtered: boolean;
  filteredReason?: string;
  breakdown: Record<string, number>;
  reasons: string[];
  evidence: string[];
  assets: string[];
  riskAssessment?: Record<string, unknown>;
  aiCalibrated?: boolean;
  raw: Record<string, unknown>;
}

// ============================================================================
// W1.1: ThreatAsset extended with v12 demo fields
// New fields are optional until W1.6 adapter populates them
// ============================================================================
export type AssetConfidence = 'direct' | 'inferred' | 'weak' | 'unknown';
export type AssetType = 'firmware' | 'image' | 'mirror' | 'openx_firmware' | string;

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
  // v12 demo fields (optional — populated by W1.6 adapter)
  type?: AssetType;
  label?: string;
  model?: string;
  version?: string;
  count?: string;
  latest?: string;
  meta?: string;
  link?: string;
  confidence?: AssetConfidence;
  repos?: string[];
  evidence?: string;
  // Per-source fields for richer asset cards
  catalog?: string[];
  syncState?: string;
  upstreamUrl?: string;
  mirrorPath?: string;
  publisher?: string;
  labelNames?: string[];
  size?: string;
  fullDescription?: string;
  cannVersion?: string;
  online?: boolean;
  official?: boolean;
  downloadCount?: number;
  deviceModel?: string;
  softwareVersion?: string;
  fileType?: string;
  hubId?: string;
  versionTags?: Array<{ tag: string; size: string; update_time: string; architectures: string[] }>;
}

// ============================================================================
// ThreatSummary (unchanged)
// ============================================================================
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

// ============================================================================
// W1.2: ThreatVulnDetail (new — 11 fields from demo v12 vulnDetails)
// ============================================================================
export type VulnSeverity = 'critical' | 'high' | 'medium' | 'low' | 'unknown' | string;
export type VulnKind = 'CVE' | 'security issue' | string;

export interface ThreatVulnDetail {
  id: string;
  kind: VulnKind;
  severity: VulnSeverity;
  title: string;
  description: string;
  source_type: string;
  source_url: string;
  source_path: string;
  published_date: string;
  matched_keywords: string[];
  patch_refs: string[];
  analysis: string;
}

export type ThreatVulnDetailMap = Record<string, ThreatVulnDetail[]>;

// ============================================================================
// W1.3: ThreatSurfaceDetail (new — with research content from demo v12 surfaceDetails)
// ============================================================================
export interface ThreatSurfaceDetail {
  id: string;
  title: string;
  count: number;
  demoCount?: number;
  top?: string;
  score: number;
  cves: number;
  secItems?: number;
  gradeA: number;
  assets: number;
  icon: string;
  desc: string;
  // Research content (4 blocks from demo v12 surfaceDetails)
  purpose: string;
  paths: string[];
  evidence: string[];
  hypotheses: string[];
}

// ============================================================================
// W1.4: Graph types
// Existing ThreatGraphNode/Edge kept for backward compat (current ThreatGraph uses them)
// New reactflow-aligned types added for W2.3/W2.4
// ============================================================================

// Existing (used by current ThreatGraph component — will be replaced in W2.4)
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

// New reactflow-aligned types (used by W2.3 buildDualTreeGraph + W2.4 ThreatGraph rewrite)
export type GraphNodeKind = 'root' | 'ecosystem' | 'repo' | 'vuln' | 'vuln-more' | 'asset-category' | 'asset';

export interface ThreatGraphData {
  kind: GraphNodeKind;
  title: string;
  meta?: string;
  score?: number;
  repoId?: string;
  assetId?: string;
  ecoId?: string;
  vulnId?: string;
}

export type ThreatReactFlowNode = Node<ThreatGraphData>;
export type ThreatReactFlowEdge = Edge;
export type GraphEdgeType = 'direct' | 'inferred' | 'weak';

// ============================================================================
// ============================================================================
// ThreatViewModel extended with v12 fields (all optional until W1.6 adapter)
// ============================================================================
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
  // v12 additions (optional — populated by W1.6 adapter)
  vulnDetails?: ThreatVulnDetailMap;
  surfaces?: ThreatSurfaceDetail[];
  activeSurface?: string;
}
