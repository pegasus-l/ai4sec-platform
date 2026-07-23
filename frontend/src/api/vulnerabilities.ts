import { getJson } from './client';
import type {
  DomainItem,
  FieldReviewRequest,
  FieldReviewResponse,
  KnowledgePayload,
  ListResponse,
  MaterialPayload,
  VulnerabilityTodayResponse,
} from '../types/vulnerability';

export function fetchVulnerabilityToday(): Promise<VulnerabilityTodayResponse> {
  return getJson('/api/vulnerabilities/today');
}

export function fetchVulnerabilityMaterials(): Promise<ListResponse<DomainItem<MaterialPayload>>> {
  return getJson('/api/vulnerabilities/materials?limit=200');
}

export function fetchVulnerabilityCandidates(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/candidates?limit=200');
}

export function fetchVulnerabilityCrawledPages(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/crawled-pages?limit=200');
}

export function fetchVulnerabilityExtractedContent(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/extracted-content?limit=200');
}

export function fetchVulnerabilityMaterialReviews(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/material-reviews?limit=200');
}

export function fetchVulnerabilityEvents(): Promise<ListResponse<DomainItem>> {
  return getJson('/api/vulnerabilities/events?limit=200');
}

export function fetchVulnerabilityExtractions(): Promise<ListResponse<DomainItem<KnowledgePayload>>> {
  return getJson('/api/vulnerabilities/extractions?limit=200');
}

export function fetchVulnerabilityKnowledge(): Promise<ListResponse> {
  return getJson('/api/vulnerabilities/knowledge');
}

export async function acceptKnowledgeField(itemId: number, fieldName: string, body: FieldReviewRequest): Promise<FieldReviewResponse> {
  return postFieldReview(itemId, fieldName, 'accept', body);
}

export async function modifyKnowledgeField(itemId: number, fieldName: string, body: FieldReviewRequest): Promise<FieldReviewResponse> {
  return postFieldReview(itemId, fieldName, 'modify', body);
}

export async function rejectKnowledgeField(itemId: number, fieldName: string, body: FieldReviewRequest): Promise<FieldReviewResponse> {
  return postFieldReview(itemId, fieldName, 'reject', body);
}

async function postFieldReview(itemId: number, fieldName: string, action: 'accept' | 'modify' | 'reject', body: FieldReviewRequest): Promise<FieldReviewResponse> {
  const response = await fetch(`/api/vulnerabilities/knowledge/${itemId}/fields/${encodeURIComponent(fieldName)}/${action}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`field review ${action}: ${response.status}`);
  return response.json() as Promise<FieldReviewResponse>;
}
