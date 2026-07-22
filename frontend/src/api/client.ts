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
      is_real_security_target: boolean;
      valid_security_findings: string[];
      false_positive_risks: string[];
      attack_surface_summary: string;
      vulnerability_hypotheses: string[];
      recommended_tracking_level: string;
      recommended_actions: string[];
      confidence: number;
    };
    recommended_actions: string[];
  };
}
