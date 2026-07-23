export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export async function postJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { method: 'POST', cache: 'no-store' });
  if (!response.ok) {
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

export async function fetchTargets(): Promise<{ items: Record<string, unknown>[] }> {
  return getJson('/api/threats/targets?limit=9999');
}

export async function fetchTrackingQueue(): Promise<{ items: Record<string, unknown>[] }> {
  return getJson('/api/threats/tracking-queue');
}

export async function fetchGraph(): Promise<{ nodes: unknown[]; edges: unknown[] }> {
  return getJson('/api/threats/graph');
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
