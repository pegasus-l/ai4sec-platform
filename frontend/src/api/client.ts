export async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { cache: 'no-store' });
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export async function postJson<T>(path: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    cache: 'no-store',
    body: body ? JSON.stringify(body) : undefined,
  });
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

export async function fetchTargets(page: number = 1, perPage: number = 50, surface: string = '', grade: string = '', search: string = ''): Promise<{ items: Record<string, unknown>[]; total: number; page: number; per_page: number; pages: number }> {
  const params = new URLSearchParams({ page: String(page), per_page: String(perPage), fields: 'summary' });
  if (surface) params.set('surface', surface);
  if (grade) params.set('grade', grade);
  if (search) params.set('search', search);
  return getJson(`/api/threats/targets?${params.toString()}`);
}

export async function fetchTrackingQueue(): Promise<{ items: Record<string, unknown>[] }> {
  return getJson('/api/threats/tracking-queue');
}

export async function trackTarget(itemId: string | number, priority: string = 'P1', reason: string = ''): Promise<{ status: string; title: string }> {
  return postJson(`/api/threats/targets/${itemId}/track`, { priority, reason });
}

export async function trackAsset(itemId: string | number, priority: string = 'P1', reason: string = ''): Promise<{ status: string; title: string }> {
  return postJson(`/api/threats/assets/${itemId}/track`, { priority, reason });
}

export async function fetchTargetDetail(itemId: string | number): Promise<Record<string, unknown>> {
  return getJson(`/api/threats/targets/${itemId}`);
}

export async function fetchGraph(): Promise<{ nodes: unknown[]; edges: unknown[] }> {
  return getJson('/api/threats/graph');
}

export interface SurfaceStats {
  total_repos: number;
  total_cves: number;
  total_sec: number;
  per_surface: Record<string, { count: number; cves: number; sec: number }>;
}

export async function fetchSurfaceStats(): Promise<SurfaceStats> {
  return getJson('/api/threats/surface-stats');
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
