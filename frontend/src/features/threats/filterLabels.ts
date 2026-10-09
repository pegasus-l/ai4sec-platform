/**
 * 仓库过滤规则代号 → 中文说明。
 *
 * 代号是后端 domains/threats/repo_filter.py 的 REASON_LABELS 的键(F1..F10 硬过滤 / S1..S2 软过滤),
 * 两边必须同步:后端落库只存代号(便于统计与回填幂等),人话在前端映射。
 */
export const FILTER_REASON_LABELS: Record<string, string> = {
  // —— 硬过滤(默认在列表里隐藏)—— //
  F1: '空壳仓:无描述、无 Star、无安全线索',
  F2: '第三方/上游镜像仓(只做同步,非自有代码)',
  F3: '赛事/活动临时仓(ghf2025 等)',
  F4: '测试/Mock/基准仓',
  F5: '文档/网站仓',
  F6: 'sample/demo/example 样例仓',
  F7: 'CI/打包胶水仓',
  F8: '教程/lab/练习仓',
  F9: '模板/脚手架仓',
  F10: '琐碎名仓(readme/license/homepage 等)',
  // —— 软过滤(仅降权,仍显示)—— //
  S1: 'SIG/治理类仓(降权)',
  S2: '发行版重打包仓(降权)',
};

export function filterReasonLabel(code?: string): string {
  if (!code) return '未标注原因';
  return FILTER_REASON_LABELS[code] ?? code;
}
