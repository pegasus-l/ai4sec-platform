import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Badge, Card, EmptyState, MetricCard } from '../../components/ui';
import { useDrawerStack } from '../../components/DrawerStack';
import {
  fetchEvalCategories, fetchEvalToolDetail, fetchEvalTools,
} from './capabilityQueries';
import type {
  EvalHeadline, EvalMetric, EvalSampleResult, EvalTool, EvalToolDetail,
} from './capabilityTypes';

/**
 * 能力评测(E1)—— 「在标准样本上判得准不准」。
 *
 * 这一页最容易犯的三个错, 代码里逐条挡:
 *  1. 把 E0(复现跑没跑起来)当成准确率 —— E0 徽标只用来交代"这个工具确实能起来",
 *     不和任何指标并排放进同一张卡。
 *  2. 把"没被评"写成"评了不行" —— latest_run 为 null 一律显示「尚未评测」, 不显示 0 分。
 *  3. 排个名 —— 20 对样本的 95% 区间有 ±0.2 宽(契约 §6), 排序等于把噪声当结论。
 *     列表顺序**照后端给的来**(E0 等级、条目 id), 页面不按任何指标重排。
 */

const METRIC_ROWS: Array<{ key: keyof EvalHeadline; label: string; tone: 'sky' | 'green' | 'amber' | 'red'; hint: string }> = [
  { key: 'locate_rate', label: '定位率', tone: 'sky', hint: '漏洞点在正确位置(严格命中或邻近命中)的比例' },
  { key: 'strict_locate_rate', label: '严格定位率', tone: 'green', hint: '行区间完全对上的比例; 比定位率严格' },
  { key: 'false_positive_rate', label: '误报率', tone: 'red', hint: '干净样本被报出漏洞的比例' },
  { key: 'balanced_accuracy', label: '平衡准确率', tone: 'amber', hint: '正负样本各占一半权重; 样本不均衡时看这个' },
];

/** 判定标签。与契约 §4.1 一一对应, 这里只做中文与配色, 不新增/合并任何一类。 */
const VERDICT: Record<string, { label: string; tone: 'green' | 'sky' | 'amber' | 'red' | 'slate' }> = {
  strict_hit: { label: '严格命中', tone: 'green' },
  near_hit: { label: '邻近命中', tone: 'sky' },
  other_hunk: { label: '命中别的改动处', tone: 'amber' },
  miss: { label: '漏报', tone: 'red' },
  false_positive: { label: '误报', tone: 'red' },
  true_negative: { label: '正确排除', tone: 'green' },
  invalid_output: { label: '输出不合契约', tone: 'amber' },
  excluded: { label: '工具声明不覆盖', tone: 'slate' },
  // 各轮结论不一致: 既不是对也不是错, 单独一类。混进"漏报"会让这份分数显得比实际更稳。
  unstable: { label: '各轮不一致', tone: 'amber' },
};

const verdictMeta = (v: string) => VERDICT[v] ?? { label: v, tone: 'slate' as const };

/** 指标值 → 百分比文字。null 是"没算出来", 不是 0 —— 显示「—」, 不补零。 */
const pct = (v: number | null | undefined): string => (v == null ? '—' : `${Math.round(v * 100)}%`);

function metricHint(m: EvalMetric | undefined): string {
  if (!m) return '无数据';
  if (m.value == null) return '未算出来';
  const [lo, hi] = m.ci95 ?? [null, null];
  const ci = lo != null && hi != null ? `95% 区间 ${pct(lo)}–${pct(hi)}` : '无区间';
  // 各轮数值不一致时明说 —— 这份分数对随机性敏感, 不能拿一次输赢去和别的工具比。
  return m.identical === false ? `${ci} · 各轮不一致` : ci;
}

// ========== 视图 ==========

export function CapabilityEval() {
  const [category, setCategory] = useState<string | null>(null);
  const { push } = useDrawerStack();

  const categoriesQ = useQuery({ queryKey: ['cap-eval-categories'], queryFn: fetchEvalCategories, staleTime: 300_000 });
  const categories = categoriesQ.data?.items ?? [];
  const activeCategory = category ?? categories[0]?.id ?? null;

  const toolsQ = useQuery({
    queryKey: ['cap-eval-tools', activeCategory],
    queryFn: () => fetchEvalTools(activeCategory ?? undefined),
    enabled: Boolean(activeCategory),
    staleTime: 60_000,
  });
  const tools = toolsQ.data?.items ?? [];

  const openTool = (tool: EvalTool) => push({
    title: tool.title,
    subtitle: `E1 · LLM 代码审计 · 单文件定位${tool.e0 ? ` · E0 L${tool.e0.level}` : ''}`,
    render: () => <EvalToolDetail itemId={tool.item_id} category={activeCategory ?? undefined} />,
  });

  return <div className="grid" style={{ paddingBottom: 48 }}>
    {/* F4 边界说明: 放在最上面, 而不是折进某个 tab。没有这段, 下面的每个数字都会被外推。 */}
    <div className="panel">
      <div className="panel-head"><h3>这一页回答什么</h3><span>E1 · 标准样本</span></div>
      <div className="panel-body">
        <p className="small" style={{ margin: 0, lineHeight: 1.8 }}>
          给定一个源码文件, 问「这里有没有漏洞、在第几行、什么类型」, 用固定的标准样本判对错。
          分数只对<b>这一类任务</b>成立。
        </p>
        <ul className="small muted" style={{ margin: '8px 0 0', paddingLeft: 18, lineHeight: 1.9 }}>
          <li><b>没被评 ≠ 评了不行</b>: 列表里的工具大多还没有评测记录, 显示「尚未评测」, 不是 0 分。</li>
          <li><b>非 Web 183 条不评</b>: E1 只覆盖 Web 类能力条目; 非 Web 的 183 条本期不做评测, 这里查不到它们。</li>
          <li><b>判据含 LLM 成分</b>: 样本的漏洞点是模型从补丁里指的, 规则只校验范围不校验唯一性。</li>
          <li><b>不做排名</b>: 样本规模下 95% 区间有 ±0.2 宽, 按分数排序会把噪声当结论, 所以这里没有排序。</li>
        </ul>
      </div>
    </div>

    {/* 类别卡片 */}
    <div className="grid cols-2" style={{ marginTop: 12 }}>
      {categories.map(cat => <div className="panel" key={cat.id}
        style={{ cursor: 'pointer', outline: activeCategory === cat.id ? '1px solid var(--accent)' : 'none' }}
        onClick={() => setCategory(cat.id)}>
        <div className="panel-head">
          <h3>{cat.name}</h3>
          <span>{cat.n_samples} 条样本 · {cat.n_runs} 次评测</span>
        </div>
        <div className="panel-body">
          <p className="small" style={{ margin: 0 }}>{cat.what}</p>
          <p className="small muted" style={{ margin: '6px 0 0' }}>测不出: {cat.cannot}</p>
          <p className="small" style={{ margin: '6px 0 0' }}>
            <Badge tone="slate">契约 {cat.contract_version}</Badge>
          </p>
        </div>
      </div>)}
      {categoriesQ.isSuccess && categories.length === 0 && <EmptyState title="没有可评测的类别" description="评测类别与样本随部署配置下发" />}
    </div>

    {/* 工具列表 */}
    <div className="panel" style={{ marginTop: 12 }}>
      <div className="panel-head">
        <h3>候选工具</h3>
        <span>{toolsQ.data?.total ?? 0} 条 · 顺序照 E0 等级与条目 id, 不按评测分数排</span>
      </div>
      <div className="panel-body">
        {toolsQ.isLoading && <p className="muted">加载中...</p>}
        {toolsQ.isError && <EmptyState title="读取失败" description="评测接口未就绪或会话已过期" />}
        {toolsQ.isSuccess && tools.length === 0 && <EmptyState title="还没有候选工具" description="E1 只对有 E0 等级的条目开放" />}
        {tools.length > 0 && <div className="table-card"><table className="data-table">
          <thead><tr><th>工具</th><th>E0 等级</th><th>样本</th><th>主指标(定位率)</th><th>结论</th><th>最近运行</th></tr></thead>
          <tbody>{tools.map(tool => {
            const run = tool.latest_run;
            const headline = run?.metrics ?? null;
            return <tr key={tool.item_id} className="clickable" onClick={() => openTool(tool)}>
              <td><div className="table-title">{tool.title}</div><div className="table-sub">item {tool.item_id}</div></td>
              <td>{tool.e0 ? <Badge tone={tool.e0.level >= 4 ? 'green' : tool.e0.level >= 2 ? 'sky' : 'amber'}>{`L${tool.e0.level}`}</Badge> : <span className="small muted">—</span>}</td>
              <td className="small">{headline?.n_samples != null ? headline.n_samples : <span className="muted">—</span>}</td>
              <td>
                {headline ? <span><b>{pct(headline.locate_rate?.value)}</b>{headline.locate_rate?.value != null && <span className="small muted"> · {metricHint(headline.locate_rate)}</span>}</span>
                  : <span className="small muted">—</span>}
              </td>
              <td>{run ? <Badge tone={run.status === 'success' ? 'green' : run.status === 'running' ? 'sky' : 'amber'}>{runStatusLabel(run.status, run.failure_reason)}</Badge>
                : <Badge tone="slate">尚未评测</Badge>}</td>
              <td className="small muted">{run?.finished_at || run?.started_at || '—'}</td>
            </tr>;
          })}</tbody>
        </table></div>}
      </div>
    </div>
  </div>;
}

function runStatusLabel(status: string, reason: string | null): string {
  if (status === 'success') return '已评测';
  if (status === 'running') return '评测中';
  if (status === 'budget_exceeded') return `超预算${reason ? ` · ${reason}` : ''}`;
  return `评测失败${reason ? ` · ${reason}` : ''}`;
}

// ========== 详情抽屉 ==========

function EvalToolDetail({ itemId, category }: { itemId: number; category?: string }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['cap-eval-tool', itemId, category],
    queryFn: () => fetchEvalToolDetail(itemId, category),
    staleTime: 60_000,
  });

  if (isLoading) return <p className="muted">加载中...</p>;
  if (isError || !data) return <EmptyState title="读取失败" description="这一条的工具详情没有取到" />;

  return <div className="grid">
    <div className="grid cols-2">
      <Card className="kpi"><span>E0 等级</span><strong>{data.e0 ? `L${data.e0.level}` : '—'}</strong></Card>
      <Card className="kpi"><span>历史评测次数</span><strong>{data.runs.length}</strong></Card>
    </div>

    {data.latest ? <EvalReport detail={data} /> : <EmptyState title="尚未评测" description="这个工具还没有跑过 E1。没被评不等于评了不行。" />}
  </div>;
}

function EvalReport({ detail }: { detail: EvalToolDetail }) {
  const latest = detail.latest!;
  const metrics = latest.metrics;
  const results = latest.results ?? [];
  const caveats = String(latest.run?.caveats ?? '').split('\n').filter(Boolean);

  return <div className="grid">
    <div className="grid cols-4" style={{ marginTop: 12 }}>
      {METRIC_ROWS.map(row => {
        const metric = metrics?.[row.key] as EvalMetric | undefined;
        return <MetricCard key={String(row.key)} label={row.label}
          value={pct(metric?.value)} hint={metricHint(metric)} tone={row.tone} />;
      })}
    </div>

    {/* 样本口径: 分母到底是多少条。少这一行, "20 条样本"会被当成"20 条都算了分"。 */}
    <div className="panel" style={{ marginTop: 12 }}>
      <div className="panel-head"><h3>这一轮的口径</h3><span>{String(latest.run?.status ?? '')}</span></div>
      <div className="panel-body">
        <p className="small" style={{ margin: 0 }}>
          样本 {metrics?.n_samples ?? '—'} 条
          {(metrics?.n_excluded ?? 0) > 0 && <>，其中 <b>{metrics!.n_excluded}</b> 条被工具声明为不覆盖、未计入分母（{Object.entries(metrics!.excluded_reasons || {}).map(([k, v]) => `${k}×${v}`).join('、')}）</>}
          ；共跑 {metrics?.repeats ?? '—'} 轮，各项指标取各轮中位数。
        </p>
        {metrics?.window?.start && metrics?.window?.end && <p className="small muted" style={{ margin: '6px 0 0' }}>
          样本公开时间 {String(metrics.window.start).slice(0, 10)} ~ {String(metrics.window.end).slice(0, 10)}
          {metrics.window.missing ? `（${metrics.window.missing} 条缺日期）` : ''}
        </p>}
        {metrics?.adaptation_verdict && <p className="small muted" style={{ margin: '6px 0 0' }}>适配结论: {metrics.adaptation_verdict}</p>}
      </div>
    </div>

    {/* caveats 与指标同屏、不可折叠 —— 契约 §6 的硬要求 */}
    {caveats.length > 0 && <div className="panel" style={{ marginTop: 12 }}>
      <div className="panel-head"><h3>读这份分数前必须知道的</h3><span>随报表一起生成</span></div>
      <div className="panel-body"><ul className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.9 }}>
        {caveats.map((line, i) => <li key={i}>{line}</li>)}
      </ul></div>
    </div>}

    {/* 不能回答什么 —— 不折叠 */}
    <div className="panel" style={{ marginTop: 12 }}>
      <div className="panel-head"><h3>这份分数回答不了什么</h3><span>{detail.cannot_answer.length} 条</span></div>
      <div className="panel-body"><ul className="small muted" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.9 }}>
        {detail.cannot_answer.map((line, i) => <li key={i}>{line}</li>)}
      </ul></div>
    </div>

    {/* 逐样本结论 */}
    <div className="panel" style={{ marginTop: 12 }}>
      <div className="panel-head"><h3>逐样本结论</h3><span>{results.length} 条</span></div>
      <div className="panel-body">
        {results.length === 0 ? <EmptyState title="这一轮没有逐样本结论" description="只落了汇总报表" /> :
          <div className="table-card"><table className="data-table">
            <thead><tr><th>样本</th><th>正负</th><th>期望</th><th>实际</th><th>各轮</th><th>判定</th></tr></thead>
            <tbody>{results.map((row: EvalSampleResult) => {
              const meta = verdictMeta(row.verdict);
              return <tr key={row.sample_id}>
                <td><div className="table-sub">{row.sample_key}</div></td>
                <td>{row.polarity === 'pre' ? <Badge tone="amber">有洞</Badge> : <Badge tone="slate">干净</Badge>}</td>
                <td className="small">{row.polarity === 'pre' ? '报出这个漏洞' : '不报'}</td>
                <td className="small">{actualText(row)}</td>
                <td className="small muted">{perRepeatText(row)}</td>
                <td><Badge tone={meta.tone}>{meta.label}</Badge></td>
              </tr>;
            })}</tbody>
          </table></div>}
      </div>
    </div>
  </div>;
}

/** 「实际」列: 只翻译工具**报了什么**(后端的 location 列就是工具报的位置, 解析不了时为空串),
 *  不从 verdict 反推 —— 拿判定去倒推行为, 会让这一列看起来总是和判定一致。 */
function actualText(row: EvalSampleResult): string {
  if (row.verdict === 'excluded') return '未作答(工具声明不覆盖)';
  if (row.verdict === 'invalid_output') return '输出不合契约, 无法判读';
  const loc = typeof row.location === 'string' ? row.location : '';
  return loc ? `报出 ${loc}` : '未报出';
}

/** 各轮判定。全部一致时只写「N 轮一致」, 免得把同一句话说 N 遍。 */
function perRepeatText(row: EvalSampleResult): string {
  const labels = (row.per_repeat ?? []).map(r => verdictMeta(String(r.label ?? '')).label);
  if (labels.length === 0) return '—';
  return new Set(labels).size === 1 ? `${labels.length} 轮一致` : labels.join(' / ');
}
