import { getJson } from './client';
import type { FrontendContract } from '../types/frontend';

export function fetchFrontendContract(): Promise<FrontendContract> {
  return getJson<FrontendContract>('/api/frontend/v9');
}
