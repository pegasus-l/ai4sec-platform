import { getJson, postJson, BASE } from '../../api/client';
import type { CapabilityItem, ReproTask, ConversionRecord, ClassifyStats, CapStats, LibraryStats, LibraryItemsResponse, LibraryFormKey, ReproBucketKey, EvalCategory, EvalTool, EvalToolDetail, EvalRunSummary, EvalHeadline, EvalSampleResult } from './capabilityTypes';

export function fetchToday(): Promise<{ items: CapabilityItem[] }> {
  return getJson('/api/capabilities/today?limit=200');
}

/** 参数化的能力库列表: 筛选/搜索/分页全部下推服务端(2026-09-15)。
 *  列表视图按 page/page_size 取一页; 三个分组视图传 limit 取整个筛选结果集(懒加载时)。 */
export function fetchLibraryPage(params: {
  q?: string;
  form?: LibraryFormKey | null;
  repro?: ReproBucketKey[];
  page?: number;
  page_size?: number;
  limit?: number;
}): Promise<LibraryItemsResponse> {
  const sp = new URLSearchParams();
  if (params.limit) sp.set('limit', String(params.limit));
  if (params.q) sp.set('q', params.q);
  if (params.form) sp.set('form', params.form);
  if (params.repro && params.repro.length > 0) sp.set('repro', params.repro.join(','));
  if (params.page) sp.set('page', String(params.page));
  if (params.page_size) sp.set('page_size', String(params.page_size));
  const qs = sp.toString();
  return getJson(`/api/capabilities/items${qs ? `?${qs}` : ''}`);
}

export function fetchLibraryStats(): Promise<LibraryStats> {
  return getJson('/api/capabilities/items/stats');
}

export function fetchDetail(id: number): Promise<CapabilityItem> {
  return getJson(`/api/capabilities/items/${id}`);
}

export function fetchReproRuns(): Promise<{ items: ReproTask[] }> {
  return getJson('/api/capabilities/repro-runs');
}

export function fetchReproTask(taskId: number): Promise<ReproTask> {
  return getJson(`/api/capabilities/repro/${taskId}`);
}

export function fetchReproFullLog(taskId: number): Promise<{ task_id: number; log: string }> {
  // 完整日志(不经 log_excerpt 的 200 行截断),用于 SSE 断流/终态后的全文兜底
  return getJson(`/api/capabilities/repro/${taskId}/log`);
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

// ========== 能力评测(E1) ==========
// 三个只读接口 + 一个发起接口。发起接口在执行位没上线时回 503 —— 前端要如实显示那句话,
// 不能吞掉当"点了没反应"。

export function fetchEvalCategories(): Promise<{ items: EvalCategory[]; runner_ready: boolean }> {
  return getJson('/api/capabilities/eval/categories');
}

export function fetchEvalTools(category?: string): Promise<{ category: string; total: number; items: EvalTool[] }> {
  const qs = category ? `?category=${encodeURIComponent(category)}` : '';
  return getJson(`/api/capabilities/eval/tools${qs}`);
}

export function fetchEvalToolDetail(itemId: number, category?: string): Promise<EvalToolDetail> {
  const qs = category ? `?category=${encodeURIComponent(category)}` : '';
  return getJson(`/api/capabilities/eval/tools/${itemId}${qs}`);
}

export function fetchEvalRun(runId: number): Promise<{ run: EvalRunSummary; metrics: EvalHeadline | null; results: EvalSampleResult[] }> {
  return getJson(`/api/capabilities/eval/runs/${runId}`);
}

export function startEvalRun(itemId: number, repeats = 3): Promise<{ run_id: number; status: string; n_samples: number }> {
  return postJson('/api/capabilities/eval/run', { item_id: itemId, repeats });
}

export function startRepro(itemId: number, web = false): Promise<{
  ok: boolean;
  task_id?: number;
  repo_url?: string;
  web_port?: number | null;
  skipped?: boolean;
  reason?: 'official_demo';
  demo_url?: string;
}> {
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
  const url = `${BASE}/api/capabilities/repro/${taskId}/logs/stream`;
  const es = new EventSource(url);

  es.addEventListener('log', (e: MessageEvent) => {
    try {
      const data = JSON.parse(e.data);
      onLog(stripAnsi(data.line), data.kind);
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
  const s = stripAnsi(line).trimStart();
  if (s.startsWith('✱') || s.startsWith('•') || s.startsWith('┌') || s.startsWith('│') || s.startsWith('└') || s.startsWith('>')) return 'tool';
  if (s.startsWith('→') || s.startsWith('[•]')) return 'read';
  if (s.startsWith('$')) return 'exec';
  if (s.startsWith('✓') || s.startsWith('[✓]')) return 'ok';
  if (s.startsWith('!') || s.startsWith('⏱')) return 'warn';
  if (s.startsWith('✗') || s.toLowerCase().includes('error') || s.toLowerCase().includes('failed') || s.includes('Traceback')) return 'error';
  return 'text';
}

export function stripAnsi(line: string): string {
  return line
    .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
    .replace(/\[[0-9]{1,3}(?:;[0-9]{1,3})*m/g, '');
}
