/**
 * 状态/结论/失败原因的**中文与配色**。只做翻译, 不做合并 ——
 *
 * 这一层最容易犯的错是把 `cannot_repro`(原文没写清) 与 `failed`(我们的环境起不来)
 * 说成同一个词。它们是两个方向的责任, 后端在写库那一层就强制配对(`tasks.VERDICT_FAILURES`),
 * 页面这里各自一类、各自一个颜色, 不提供"失败"这种合并选项。
 */

type Tone = 'green' | 'sky' | 'amber' | 'red' | 'violet' | 'slate';

export interface Meta { label: string; tone: Tone; hint?: string }

export const STATUS_META: Record<string, Meta> = {
  pending: { label: '待生成 spec', tone: 'slate', hint: '有素材, 还没把"怎么算复现成功"写成可执行步骤' },
  spec_ready: { label: 'spec 就绪', tone: 'sky', hint: '步骤已生成并通过校验, 还没开跑' },
  queued: { label: '排队中', tone: 'sky', hint: '等复现名额(与能力库复现共用名额池)' },
  running: { label: '执行中', tone: 'sky', hint: '真会话在跑, 证据边跑边落库' },
  success: { label: '复现成功', tone: 'green', hint: '判据命中, 证据无缺口' },
  partial: { label: '部分复现', tone: 'amber', hint: '跑到了, 但判据没完全命中或证据有缺口' },
  failed: { label: '执行失败', tone: 'red', hint: '我们的问题: 环境没起来 / 执行异常' },
  cannot_repro: { label: '原文不可复现', tone: 'violet', hint: '原文的问题: 没写清、版本对不上 —— 不是我们没做出来' },
  blocked: { label: '被安全边界拦下', tone: 'red', hint: '执行里出现了对公网目标的真实请求, 主动终止' },
  cancelled: { label: '已取消', tone: 'slate', hint: '人停的, 没有结论' },
  spec_failed: { label: 'spec 生成失败', tone: 'slate', hint: '连续几次都没建出能对上原文的 spec —— 我们的问题' },
};

export const statusMeta = (status: string): Meta => STATUS_META[status] ?? { label: status || '未知', tone: 'slate' };

export const VERDICT_META: Record<string, Meta> = {
  success: { label: '复现成功', tone: 'green' },
  partial: { label: '部分复现', tone: 'amber' },
  failed: { label: '执行失败', tone: 'red' },
  cannot_repro: { label: '原文不可复现', tone: 'violet' },
  blocked: { label: '被安全边界拦下', tone: 'red' },
};

export const verdictMeta = (verdict: string): Meta => VERDICT_META[verdict] ?? { label: verdict || '无结论', tone: 'slate' };

export const FAILURE_LABELS: Record<string, string> = {
  article_incomplete: '原文没写清攻击过程',
  version_mismatch: '版本对不上',
  probe_not_matched: '判据没命中',
  review_conflict: '复核与结论冲突',
  degraded: '证据有缺口(降级)',
  env_error: '环境/执行出错(我们的锅)',
  online_target: '命中公网目标(安全边界)',
};

export const failureLabel = (reason: string): string => (reason ? FAILURE_LABELS[reason] ?? reason : '');

export const TRIGGER_LABELS: Record<string, string> = { manual: '手动发起', pipeline: '管线发起', rerun: '重跑' };
export const triggerLabel = (trigger: string): string => TRIGGER_LABELS[trigger] ?? trigger ?? '';

/** 归因方向。success 没有归因(后端会把模型塞的占位值清空并记 caveat)。 */
export const SIDE_LABELS: Record<string, string> = {
  article: '原文的问题',
  ours: '我们的问题',
  objective: '客观边界(靶场/网络)',
};

/** 归因方向。**空串而不是「未知」** —— 报告没写方向时页面应该什么都不显示, 不能替它编一个。 */
export const sideLabel = (side?: string | null): string => (side ? SIDE_LABELS[side] ?? side : '');

/** 判据三值: 判不了 ≠ 没命中。null 必须单独一种说法, 不能落到"失败"。 */
export function matchedMeta(matched: boolean | null | undefined): { text: string; tone: Tone } {
  if (matched === true) return { text: '已命中', tone: 'green' };
  if (matched === false) return { text: '没命中', tone: 'amber' };
  return { text: '判不了(退出码不可知)', tone: 'slate' };
}

export function fmtDuration(seconds: number | null | undefined): string {
  if (seconds == null) return '—';
  if (seconds < 60) return `${seconds} 秒`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return rest ? `${minutes} 分 ${rest} 秒` : `${minutes} 分`;
}

/** 库里存的是 UTC 秒级时间戳(`2026-11-13T10:22:12Z`), 页面统一显示到分钟。 */
export function fmtTime(value: string | null | undefined): string {
  if (!value) return '—';
  const text = String(value).replace('T', ' ').replace('Z', '');
  return text.slice(0, 16);
}
