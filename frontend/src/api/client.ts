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
