import { getJson, postJson } from '../../api/client';
import type { CapabilityItem, ReproTask, ConversionRecord, ClassifyStats, CapStats } from './capabilityTypes';

export function fetchToday(): Promise<{ items: CapabilityItem[] }> {
  return getJson('/api/capabilities/today?limit=12');
}

export function fetchLibrary(limit = 50): Promise<{ items: CapabilityItem[] }> {
  return getJson(`/api/capabilities/items?limit=${limit}`);
}

export function fetchDetail(id: number): Promise<CapabilityItem> {
  return getJson(`/api/capabilities/items/${id}`);
}

export function fetchReproRuns(): Promise<{ items: ReproTask[] }> {
  return getJson('/api/capabilities/repro-runs');
}

export function fetchConversions(): Promise<{ items: ConversionRecord[] }> {
  return getJson('/api/capabilities/conversions');
}

export function fetchClassifyStats(): Promise<ClassifyStats> {
  return getJson('/api/capabilities/classify/stats');
}

export function fetchStats(): Promise<CapStats> {
  return getJson('/api/capabilities/stats');
}

export function startRepro(itemId: number, web = false): Promise<{ ok: boolean; task_id: number; repo_url: string; web_port: number | null }> {
  return postJson(`/api/capabilities/items/${itemId}/start-repro`, { web });
}

export function stopRepro(taskId: number): Promise<{ ok: boolean }> {
  return postJson(`/api/capabilities/repro/${taskId}/stop`);
}

export function cleanupRepro(taskId: number): Promise<{ ok: boolean }> {
  return postJson(`/api/capabilities/repro/${taskId}/cleanup`);
}

export function markConversion(itemId: number, data: { status: string; scenario: string; owner: string; next_action: string; notes: string }): Promise<{ ok: boolean; conversion_id: number; status: string }> {
  return postJson(`/api/capabilities/items/${itemId}/mark-conversion`, data);
}

export function classifyBatch(limit = 50): Promise<{ ok: boolean; classified: number; failed: number }> {
  return postJson(`/api/capabilities/classify/batch?limit=${limit}`);
}

/**
 * SSE 实时日志流（决策 4: SSE 替代 WebSocket）
 * 返回 cleanup 函数，调用后关闭 EventSource
 */
export function streamReproLogs(
  taskId: number,
  onLog: (line: string, kind: string) => void,
  onStatus: (status: string, report: unknown) => void,
  onEnd: () => void
): () => void {
  const url = `/api/capabilities/repro/${taskId}/logs/stream`;
  const es = new EventSource(url);

  es.addEventListener('log', (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data);
      onLog(data.line, data.kind);
    } catch { /* ignore parse errors */ }
  });

  es.addEventListener('status', (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data);
      onStatus(data.status, data.report);
    } catch { /* ignore */ }
  });

  es.addEventListener('end', () => {
    es.close();
    onEnd();
  });

  es.onerror = () => {
    es.close();
    onEnd();
  };

  return () => es.close();
}

/** 日志行分类（迁自后端 classify_log_line，7 类上色） */
export function classifyLogLine(line: string): string {
  const s = line.trimStart();
  if (s.startsWith('✱') || s.startsWith('•') || s.startsWith('┌') || s.startsWith('│') || s.startsWith('└') || s.startsWith('>')) return 'tool';
  if (s.startsWith('→') || s.startsWith('[•]')) return 'read';
  if (s.startsWith('$')) return 'exec';
  if (s.startsWith('✓') || s.startsWith('[✓]')) return 'ok';
  if (s.startsWith('!') || s.startsWith('⏱')) return 'warn';
  if (s.startsWith('✗') || s.toLowerCase().includes('error') || s.toLowerCase().includes('failed') || s.includes('Traceback')) return 'error';
  return 'text';
}
