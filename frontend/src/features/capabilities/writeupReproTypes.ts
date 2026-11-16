/**
 * writeup 复现(T6)前端类型。
 *
 * 形状照**线上库里真实的行**声明, 不是照设计稿: 报告的八个 JSON 列在库上是 TEXT, 读出来
 * 已被后端解析成对象(`report._parse_report_row`), 但里面的键是模型写的, 随时可能少一个 ——
 * 所以这里每个字段都是可选的, 页面一律走 `?? ''` / 空态, 不假设"它一定在"。
 *
 * 只声明页面要渲染的字段。接口多给的键照旧带过, 后端加字段不该让前端编译失败。
 */

export type Json = Record<string, unknown>;

/** 任务状态。`spec_failed` 是**我们的**问题(反复建不出可核对的 spec), 不并进 cannot_repro。 */
export type WriteupStatus =
  | 'pending' | 'spec_ready' | 'queued' | 'running'
  | 'success' | 'partial' | 'failed' | 'cannot_repro' | 'blocked' | 'cancelled' | 'spec_failed';

export type WriteupVerdict = 'success' | 'partial' | 'failed' | 'cannot_repro' | 'blocked';

export interface WriteupMaterialRef {
  id: number;
  title: string;
  url: string;
}

/** 三件产物有没有。列表接口只给布尔, 正文在 `/tasks/{id}/products`。 */
export interface WriteupProducts {
  report: boolean;
  recipe: boolean;
  pattern: boolean;
}

// ---------------------------------------------------------------- spec

export interface WriteupSpecStep {
  run: string;
  expect?: string;
  /** 这一步对应报告第 3 节哪条命令 —— 抽出来的步骤必须能回指证据。 */
  source_quote?: string;
  index?: number;
}

export interface WriteupSpec {
  sufficient?: boolean;
  claim?: string;
  claim_quote?: string;
  target?: { kind?: string; repo?: string; ref?: string; setup?: string[] };
  steps?: WriteupSpecStep[];
  probe?: { type?: string; cmd?: string; success_signal?: string };
  verification?: {
    strict?: boolean;
    claim_quote_checked?: boolean;
    steps_checked?: number;
    root_cause_provenance?: string;
    notes?: string[];
  };
  root_cause?: Json;
  verification_notes?: string[];
}

// ---------------------------------------------------------------- 证据包

export interface EvidenceCommand {
  index?: number;
  cmd: string;
  exit_code?: number | null;
  completed?: boolean;
  stdout_sha1?: string;
  stdout_tail?: string;
  stdout_chars?: number;
}

export interface EvidenceProbe {
  found?: boolean;
  spec_cmd?: string;
  cmd?: string;
  exit_code?: number | null;
  shell_exit_code?: number | null;
  exit_code_source?: string;
  success_signal?: string;
  /** 三值: true 命中 / false 没命中 / null 判不了(退出码不可知) —— 判不了 ≠ 没命中。 */
  matched?: boolean | null;
  occurrences?: number;
  why?: string;
  checks?: Json[];
}

export interface EvidenceJson {
  /** 报告第 3 节: 平台从 transcript 里摘出来的命令(不读 agent 自述)。 */
  section?: {
    speaker?: string;
    commands?: EvidenceCommand[];
    command_count?: number;
    duration_seconds?: number;
    tool_calls?: number;
  };
  /** 完整证据包(执行器落库的那一份)。 */
  pack?: {
    version?: number;
    collected_at?: string;
    commands?: EvidenceCommand[];
    probe?: EvidenceProbe;
    egress?: Json;
    guard?: Json;
    agent_claim?: Json;
    duration_seconds?: number;
    tool_calls?: number;
    incomplete?: boolean;
    incomplete_reasons?: string[];
  };
  generation?: {
    version?: number;
    generated_at?: string;
    root_cause_source?: string;
    root_cause_verified?: boolean;
    pattern_verified?: boolean;
    provider?: string;
    model?: string;
    prompt_chars?: number;
  };
}

// ---------------------------------------------------------------- 报告八节

export interface ClaimJson {
  speaker?: string;
  claim?: string;
  claim_quote?: string;
  claimed_effect?: string;
  evidence_quote?: string;
  poc_lang?: string;
  env_hint?: string;
  target?: { kind?: string; repo?: string; version?: string };
  target_cve?: string;
  target_product?: string;
  source?: { material_id?: number; title?: string; url?: string };
}

export interface ObservedJson {
  speaker?: string;
  probe_found?: boolean;
  matched?: boolean | null;
  success_signal?: string;
  spec_cmd?: string;
  cmd?: string;
  exit_code?: number | null;
  shell_exit_code?: number | null;
  exit_code_source?: string;
  stdout_sha1?: string;
  stdout_tail?: string;
  occurrences?: number;
  checks?: Json[];
  why?: string;
  expected_effect?: string;
  evidence_gaps?: string[];
  agent_self_report?: Json;
}

export interface AttributionJson {
  speaker?: string;
  side?: string;
  model_side?: string;
  reason?: string;
  model_reason?: string;
  evidence_refs?: Array<number | string>;
  expected_side?: string;
  verdict?: string;
  failure_reason?: string;
}

export interface RootCauseJson {
  location?: { file?: string; function?: string; lines?: string };
  invariant?: string;
  broken_by?: string;
  preconditions?: string[];
  code_quote?: string;
  speaker?: string;
  checked_against?: string;
  /** `from_article` / `llm_extracted` / `llm_extracted_unverified` —— 第 6 节是否在原文里对上过。 */
  provenance?: string;
  caveats?: string[];
}

export interface PatternJson {
  speaker?: string;
  invariant?: string;
  code_feature?: string;
  audit_entry?: string;
  discriminator?: string;
  generalization?: string;
  provenance?: string;
  confidence?: number | null;
  evidence_refs?: Array<number | string>;
  root_cause_provenance?: string;
  /** 第 7 节入库闸门的结论。false 时 blockers 写明卡在哪。 */
  verified?: boolean;
  blockers?: string[];
}

export interface WriteupReport {
  task_id: number;
  material_id: number;
  verdict: string;
  failure_reason: string;
  claim_json: ClaimJson;
  observed_json: ObservedJson;
  attribution_json: AttributionJson;
  root_cause_json: RootCauseJson;
  pattern_json: PatternJson;
  evidence_json: EvidenceJson;
  caveats: string[];
  generated_by: string;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  created_at: string;
}

// ---------------------------------------------------------------- 任务

export interface WriteupTask {
  id: number;
  material_id: number;
  attempt: number;
  case_id: number | null;
  claim: string;
  claim_quote: string;
  target_kind: string;
  target_repo: string;
  target_version: string;
  spec_json: WriteupSpec;
  spec_source: string;
  spec_attempts: number;
  status: string;
  verdict: string;
  failure_reason: string;
  review_verdict: string;
  review_reason: string;
  recipe_id: number | null;
  container_name: string;
  session_id: string;
  evidence_json: EvidenceJson;
  recipe_json: Json;
  log: string;
  duration_seconds: number | null;
  tool_calls: number | null;
  trigger: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  finished_at: string | null;
  /** 列表接口补的: 这条任务跑的是哪篇文章。素材被删过就是 null(不是空标题)。 */
  material?: WriteupMaterialRef | null;
  products?: WriteupProducts;
  /**
   * 同一素材的**全部尝试**, 按遍数升序(列表接口补的)。
   *
   * 列表默认按素材折叠, 一篇 writeup 只出现一行 —— 所以"另外两遍跑成了什么样"
   * 必须跟在这一行上, 否则用户得靠切筛选才能拼出历史。
   */
  attempts?: WriteupAttemptBrief[];
}

/** 一条尝试的摘要(折叠视图里的历史条)。 */
export interface WriteupAttemptBrief {
  id: number;
  material_id: number;
  attempt: number;
  status: string;
  verdict: string;
  failure_reason: string;
  created_at: string;
  finished_at: string | null;
}

// ---------------------------------------------------------------- 固化产物

export interface RecipeStep {
  index?: number | null;
  cmd: string;
  exit_code?: number | null;
  [key: string]: unknown;
}

export interface RecipeProbe {
  index?: number | null;
  cmd?: string;
  exit_code?: number | null;
  shell_exit_code?: number | null;
  exit_code_source?: string;
  success_signal?: string;
  matched?: boolean | null;
  occurrences?: number;
  index_found?: boolean;
}

export interface RecipeJson {
  version?: number;
  applies_to?: { fingerprint?: string[]; target_kind?: string };
  acquire?: RecipeStep[];
  setup?: RecipeStep[];
  trigger?: RecipeStep[];
  probe?: RecipeProbe;
  target?: Json;
  known_pitfalls?: string[];
  degraded?: boolean;
  omitted?: Array<Record<string, unknown>>;
  truncated?: number | Record<string, unknown> | null;
  verified_on?: string[];
  source?: {
    task_id?: number;
    material_id?: number;
    attempt?: number;
    verdict?: string;
    duration_seconds?: number | null;
    tool_calls?: number | null;
  };
}

export interface WriteupRecipeRow {
  id: number;
  recipe_key: string;
  task_id: number;
  material_id: number;
  fingerprint_json: string[];
  recipe_json: RecipeJson;
  /** true = 来源是 partial(只做到一半的成功路径), 复用时先看这个标记。
   *  后端的 `_parse_recipe_row` 已把库里的 0/1 解析成布尔, 所以这里不是 number。 */
  degraded: boolean;
  success_count: number;
  fail_count: number;
  created_at: string;
  updated_at: string;
}

export interface WriteupPatternRow {
  id: number;
  report_id: number;
  material_id: number;
  invariant: string;
  code_feature: string;
  audit_entry: string;
  discriminator: string;
  generalization: string;
  fingerprint: string[];
  provenance: string;
  confidence: number | null;
  created_at: string;
}

export interface WriteupProductsDetail {
  recipe: WriteupRecipeRow | null;
  pattern: WriteupPatternRow | null;
}

/** 一条会导出到审计 skill 的文件。markdown 由后端渲染, 与磁盘上的文件同源。 */
export interface WriteupSkillFile {
  kind: 'verified' | 'case' | 'catalog';
  /** skill 根目录下的相对路径, 如 references/verified/material-132734.md。 */
  path: string;
  markdown: string;
  chars: number;
}

export interface WriteupSkillExport {
  skill: string;
  task_id: number;
  material_id: number | null;
  title?: string;
  files: WriteupSkillFile[];
  /** files 为空时的原因 —— "没东西可导出"是结论, 不是故障。 */
  note?: string;
}

// ---------------------------------------------------------------- 统计

export interface WriteupStats {
  total: number;
  /**
   * 按素材去重的任务数。折叠视图上的芯片数字用这个 —— 芯片写 3、列表只有 1 张卡
   * 等于让用户以为筛选坏了。
   */
  materials: number;
  by_status: Record<string, number>;
  by_verdict: Record<string, number>;
  /** 与 by_verdict 同口径但按素材去重(折叠视图的芯片用)。 */
  by_verdict_materials: Record<string, number>;
  by_failure_reason: Record<string, number>;
  /** 未结束的任务数(pending → running)。 */
  active: number;
  /** 与 active 同口径但按素材去重(折叠视图用)。 */
  active_materials: number;
  spec_source: Record<string, number>;
  products: {
    recipes: number;
    degraded_recipes: number;
    patterns: number;
    pattern_materials: number;
  };
}
