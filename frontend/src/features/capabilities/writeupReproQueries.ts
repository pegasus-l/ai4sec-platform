import { getJson, postJson } from '../../api/client';
import type {
  WriteupMetrics, WriteupPatternRow, WriteupProductsDetail, WriteupRecipeRow, WriteupReport, WriteupSkillExport,
  WriteupStats, WriteupTask,
} from './writeupReproTypes';

/**
 * writeup 复现的只读/写接口。**路径前缀 `/api/writeup-repro`** —— 与能力洞察的
 * `/api/capabilities/*` 不是一套: 复现跑的是真会话、真容器, 与能力库的 cron 复现是两条链。
 */

export interface TaskQuery {
  status?: string;
  verdict?: string;
  /** true = 未结束(pending/spec_ready/queued/running); false = 终态。与 status 互斥。 */
  active?: boolean;
  material_id?: number;
  /** true = 按素材折叠, 一篇 writeup 只有一行(重跑会开出多行)。默认折叠。 */
  latestOnly?: boolean;
  limit?: number;
  offset?: number;
}

export interface TaskPage {
  items: WriteupTask[];
  total: number;
  limit: number;
  offset: number;
}

export function fetchTasks(query: TaskQuery = {}): Promise<TaskPage> {
  const sp = new URLSearchParams();
  if (query.status) sp.set('status', query.status);
  if (query.verdict) sp.set('verdict', query.verdict);
  // 布尔要显式写字符串: `active=false` 与"不给这个参数"是两件事(后者 = 两档都要)。
  if (query.active !== undefined) sp.set('active', String(query.active));
  if (query.material_id) sp.set('material_id', String(query.material_id));
  if (query.latestOnly) sp.set('latest_only', 'true');
  sp.set('limit', String(query.limit ?? 20));
  sp.set('offset', String(query.offset ?? 0));
  return getJson<TaskPage>(`/api/writeup-repro/tasks?${sp.toString()}`);
}

export function fetchTask(taskId: number): Promise<WriteupTask> {
  return getJson<WriteupTask>(`/api/writeup-repro/tasks/${taskId}`);
}

export function fetchStats(): Promise<WriteupStats> {
  return getJson<WriteupStats>('/api/writeup-repro/stats');
}

/**
 * 报告。**没生成过是 404, 不是错误** —— 执行器会自动生成, 但 T4.3 之前跑完的老任务没有报告,
 * 页面必须能把"还没有报告"与"接口挂了"分开: 前者显示一个可点的「生成报告」, 后者显示报错。
 */
export async function fetchReport(taskId: number): Promise<WriteupReport | null> {
  try {
    const data = await getJson<{ report: WriteupReport }>(`/api/writeup-repro/tasks/${taskId}/report`);
    return data.report;
  } catch (error) {
    if ((error as Error)?.message?.endsWith(': 404')) return null;
    throw error;
  }
}

/** 这一条任务存着的 recipe / pattern(正文)。列表只给"有没有"。 */
export function fetchProducts(taskId: number): Promise<WriteupProductsDetail> {
  return getJson<WriteupProductsDetail>(`/api/writeup-repro/tasks/${taskId}/products`);
}

/**
 * 这条任务会导出成哪些审计 skill 文件(渲染好的 markdown)。
 *
 * **不要用 `fetchProducts` 自己拼一份** —— 页面预览必须与磁盘上的
 * `references/verified/*.md` 是同一串字符, 两边各拼一份迟早不一致。
 */
export function fetchTaskSkill(taskId: number): Promise<WriteupSkillExport> {
  return getJson<WriteupSkillExport>(`/api/writeup-repro/tasks/${taskId}/skill`);
}

export interface RecipeQuery {
  fingerprint?: string;
  degraded?: boolean;
  limit?: number;
  offset?: number;
}

export function fetchRecipes(query: RecipeQuery = {}): Promise<{ items: WriteupRecipeRow[]; total: number }> {
  const sp = new URLSearchParams();
  if (query.fingerprint) sp.set('fingerprint', query.fingerprint);
  if (query.degraded !== undefined) sp.set('degraded', String(query.degraded));
  sp.set('limit', String(query.limit ?? 20));
  sp.set('offset', String(query.offset ?? 0));
  return getJson(`/api/writeup-repro/recipes?${sp.toString()}`);
}

export interface PatternQuery {
  fingerprint?: string;
  generalization?: string;
  limit?: number;
  offset?: number;
}

export function fetchPatterns(query: PatternQuery = {}): Promise<{ items: WriteupPatternRow[]; total: number }> {
  const sp = new URLSearchParams();
  if (query.fingerprint) sp.set('fingerprint', query.fingerprint);
  if (query.generalization) sp.set('generalization', query.generalization);
  sp.set('limit', String(query.limit ?? 20));
  sp.set('offset', String(query.offset ?? 0));
  return getJson(`/api/writeup-repro/patterns?${sp.toString()}`);
}

// ---------------------------------------------------------------- 写操作

/** 建任务。同一素材重复建**不插新行**, 返回已有的那一条(created=false)。 */
export function createTask(materialId: number, caseId?: number): Promise<{ task: WriteupTask; created: boolean }> {
  return postJson('/api/writeup-repro/tasks', { material_id: materialId, case_id: caseId ?? null, trigger: 'manual' });
}

/** 调模型生成 spec 并校验。引用对不上会 502(已丢弃、下一轮重试), 原文没写清会落 cannot_repro。 */
export function generateSpec(taskId: number): Promise<{ task: WriteupTask }> {
  return postJson(`/api/writeup-repro/tasks/${taskId}/spec`);
}

/** 真跑一遍。**后台线程**, 立刻返回; started=false 表示已有线程在跑(不双跑)。 */
export function runTask(taskId: number, timeout?: number): Promise<{ started: boolean; reason: string; task: WriteupTask }> {
  const qs = timeout ? `?timeout=${timeout}` : '';
  return postJson(`/api/writeup-repro/tasks/${taskId}/run${qs}`);
}

export function stopTask(taskId: number): Promise<{ signalled: boolean }> {
  return postJson(`/api/writeup-repro/tasks/${taskId}/stop`);
}

export function cancelTask(taskId: number): Promise<{ task: WriteupTask }> {
  return postJson(`/api/writeup-repro/tasks/${taskId}/cancel`);
}

/** 重跑 = **新开 attempt+1 一行**, 上一行(含证据与结论)原样保留。只收终态。 */
export function rerunTask(taskId: number, start = true): Promise<{ task: WriteupTask; rerun_of: number; started: boolean; reason: string }> {
  return postJson(`/api/writeup-repro/tasks/${taskId}/rerun?start=${start ? 'true' : 'false'}`);
}

/** 生成/重生成报告。模型报错 → 502/503 且**一行不写**(库里仍是空, 可重试)。 */
export function generateReport(taskId: number): Promise<{ status: string; report: WriteupReport }> {
  return postJson(`/api/writeup-repro/tasks/${taskId}/report`);
}

/** 从报告抽 recipe + pattern。抽不出来是 200 + reasons(结论不支持), 不是接口故障。 */
export function extractProducts(taskId: number): Promise<{ status: string; reasons?: string[] }> {
  return postJson(`/api/writeup-repro/tasks/${taskId}/extract`);
}

export function fetchMetrics(): Promise<WriteupMetrics> {
  return getJson<WriteupMetrics>('/api/writeup-repro/metrics');
}
