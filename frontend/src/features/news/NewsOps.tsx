import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Activity, CheckCircle2, Database, FileText, Play, RefreshCw, Server, Workflow } from 'lucide-react';
import { useState } from 'react';
import { Badge, Card, Drawer, EmptyState, MetricCard } from '../../components/ui';
import { fetchNewsOps, fetchNewsRun, startNewsPipeline } from './newsQueries';
import type { NewsView } from './newsTypes';

type Run = { run_id: string; pipeline_name: string; status: string; started_at: string; finished_at: string; production_writes: number; summary: Record<string, unknown>; task_counts: Record<string, number> };
type Task = { id: number; step_name: string; status: string; started_at: string; finished_at: string; metrics: Record<string, unknown>; error_message: string };
type Artifact = { id: number; artifact_type: string; path: string; bytes: number };
type ModelMetrics = { total: number; success: number; failed: number; retryable_failure: number; avg_latency_ms: number; agents: Array<{ agent_name: string; provider: string; model_profile: string; total: number; success: number; failed: number; retryable_failure: number; avg_latency_ms: number }> };
type RunDetail = Run & { tasks: Task[]; artifacts: Artifact[]; models: ModelMetrics };
type Source = { id: string; name: string; status: string; health: string; latest_at: string; item_count: number; summary: Record<string, unknown> };

const sourceNames: Record<string, string> = { arxiv: 'arXiv', github: 'GitHub', rss: 'RSS', asis: 'ASIS', awesome: 'Awesome', x: 'X' };
const stepNames: Record<string, string> = { collect_news_sources: '采集数据源', extract_news_references: '发现论文与项目', normalize_news: '标准化', deduplicate_news: '去重', resolve_news_links: '论文项目关联', gate_news_candidates: '技术地图门控', enrich_news_candidates: '深度评审', build_news_items: '构建资讯条目', build_news_daily_report: '生成日报', audit_news: '质量审计' };

export function NewsOps({ view, setView }: { view: NewsView; setView: (view: NewsView) => void }) {
  if (view === 'ops-runs') return <Runs />;
  if (view === 'ops-sources') return <Sources />;
  if (view === 'ops-quality') return <Quality />;
  return <Overview setView={setView} />;
}

function Overview({ setView }: { setView: (view: NewsView) => void }) {
  const queryClient = useQueryClient();
  const query = useQuery({ queryKey: ['news-ops', 'overview'], queryFn: () => fetchNewsOps<{ items: { total: number; papers: number; projects: number }; latest_run: Run | null; latest_report: { report_date: string; title: string } | null; sources: Source[]; models: ModelMetrics }>('overview'), refetchInterval: 5000 });
  const run = useMutation({ mutationFn: () => startNewsPipeline(), onSuccess: () => queryClient.invalidateQueries({ queryKey: ['news-ops'] }) });
  if (!query.data) return <Loading />;
  const data = query.data;
  const healthy = data.sources.filter(source => ['ok', 'healthy', 'success'].includes(source.health) || ['ok', 'success'].includes(source.status)).length;
  return <div className="news-ops-stack">
    <div className="news-kpis"><MetricCard label="资讯总量" value={data.items.total} hint="已入库论文与项目" /><MetricCard label="论文" value={data.items.papers} hint="paper" /><MetricCard label="项目" value={data.items.projects} hint="project" /><MetricCard label="健康数据源" value={`${healthy}/6`} hint="最近采集状态" /></div>
    <div className="news-ops-grid"><Card><div className="ops-card-title"><Workflow size={17} /><h3>最新 Pipeline</h3><Status value={data.latest_run?.status || 'unknown'} /></div>{data.latest_run ? <><strong className="ops-run-name">{data.latest_run.pipeline_name}</strong><p>{formatTime(data.latest_run.started_at)} → {formatTime(data.latest_run.finished_at)}</p><div className="ops-actions"><button onClick={() => setView('ops-runs')}>查看运行详情</button><button className="primary" disabled={run.isPending || data.latest_run.status === 'running'} onClick={() => run.mutate()}><Play size={14} />{run.isPending ? '正在启动' : '运行完整 Pipeline'}</button></div></> : <EmptyState title="暂无运行记录" description="运行资讯 Pipeline 后将在这里显示进度。" />}</Card><Card><div className="ops-card-title"><Activity size={17} /><h3>模型评审</h3></div><div className="ops-mini-grid"><span><b>{data.models.total}</b>调用</span><span><b>{data.models.success}</b>成功</span><span><b>{data.models.failed}</b>失败</span><span><b>{data.models.avg_latency_ms}ms</b>平均延迟</span></div><button className="ops-link" onClick={() => setView('ops-quality')}>查看门控与深评质量 →</button></Card></div>
    <div className="news-ops-grid"><Card><div className="ops-card-title"><Server size={17} /><h3>六数据源</h3></div><div className="ops-source-strip">{data.sources.map(source => <button key={source.id} onClick={() => setView('ops-sources')}><Status value={source.health || source.status} /><b>{sourceNames[source.id]}</b><span>{source.item_count} 条</span></button>)}</div></Card><Card><div className="ops-card-title"><FileText size={17} /><h3>日报产物</h3></div>{data.latest_report ? <><strong className="ops-run-name">{data.latest_report.title}</strong><p>最新日报：{data.latest_report.report_date}</p></> : <p className="muted">尚未生成日报，完成 Pipeline 后自动生成。</p>}</Card></div>
  </div>;
}

function Runs() {
  const [selected, setSelected] = useState('');
  const query = useQuery({ queryKey: ['news-ops', 'runs'], queryFn: () => fetchNewsOps<{ items: Run[] }>('runs'), refetchInterval: 5000 });
  const detail = useQuery({ queryKey: ['news-ops-run', selected], queryFn: () => fetchNewsRun<RunDetail>(selected), enabled: Boolean(selected), refetchInterval: selected ? 3000 : false });
  return <div className="news-ops-stack"><Card><div className="ops-card-title"><Workflow size={17} /><h3>Pipeline 运行历史</h3><span className="muted">点击查看步骤、模型调用和产物</span></div>{!query.data?.items.length ? <EmptyState title="暂无运行记录" description="从运营概览启动一次完整 Pipeline。" /> : <div className="ops-run-list">{query.data.items.map(run => <button key={run.run_id} onClick={() => setSelected(run.run_id)}><Status value={run.status} /><div><strong>{run.pipeline_name}</strong><span>{run.run_id}</span></div><span>{formatTime(run.started_at)}</span><span>{Object.values(run.task_counts || {}).reduce((sum, value) => sum + value, 0)} 步</span></button>)}</div>}</Card><RunDrawer data={detail.data} open={Boolean(selected)} close={() => setSelected('')} /></div>;
}

function RunDrawer({ data, open, close }: { data?: RunDetail; open: boolean; close: () => void }) {
  return <Drawer open={open} title={data?.pipeline_name || '正在加载运行详情'} subtitle={data?.run_id} onClose={close}>{data && <div className="news-detail"><Card><div className="ops-card-title"><Status value={data.status} /><span>{formatTime(data.started_at)} → {formatTime(data.finished_at)}</span></div><p>Shadow 模式：{data.production_writes ? '否' : '是'}</p></Card><div className="ops-steps">{data.tasks.map((task, index) => <Card key={task.id}><div className="ops-step-index">{index + 1}</div><div><div className="ops-card-title"><strong>{stepNames[task.step_name] || task.step_name}</strong><Status value={task.status} /></div><p>{compactMetrics(task.metrics)}</p>{task.error_message && <div className="ops-error">{task.error_message}</div>}</div></Card>)}</div><Card><h3>模型调用</h3><p>共 {data.models.total} 次 · 成功 {data.models.success} · 失败 {data.models.failed} · 重试 {data.models.retryable_failure}</p></Card><Card><h3>原始与中间产物 · {data.artifacts.length}</h3>{data.artifacts.map(item => <div className="ops-artifact" key={item.id}><Database size={14} /><span>{item.artifact_type}</span><code>{item.path}</code></div>)}</Card></div>}</Drawer>;
}

function Sources() {
  const query = useQuery({ queryKey: ['news-ops', 'sources'], queryFn: () => fetchNewsOps<{ items: Source[] }>('sources'), refetchInterval: 10000 });
  return <div className="ops-source-grid">{query.data?.items.map(source => <Card key={source.id}><div className="ops-card-title"><Server size={17} /><h3>{sourceNames[source.id]}</h3><Status value={source.health || source.status} /></div><strong className="ops-source-count">{source.item_count}</strong><span className="muted">当前入库条目</span><dl><dt>最近更新</dt><dd>{formatTime(source.latest_at)}</dd><dt>运行状态</dt><dd>{source.status}</dd><dt>采集摘要</dt><dd>{compactMetrics(source.summary)}</dd></dl></Card>)}</div>;
}

function Quality() {
  const query = useQuery({ queryKey: ['news-ops', 'quality'], queryFn: () => fetchNewsOps<{ run_id: string; tasks: Task[]; models: ModelMetrics; audits: Array<{ id: number; audit_type: string; status: string; score: number; summary: string }> }>('quality'), refetchInterval: 10000 });
  if (!query.data) return <Loading />;
  return <div className="news-ops-stack"><Card><div className="ops-card-title"><Activity size={17} /><h3>最新运行处理漏斗</h3><span className="muted">{query.data.run_id || '暂无运行'}</span></div><div className="ops-funnel">{query.data.tasks.map(task => <div key={task.id}><Status value={task.status} /><strong>{stepNames[task.step_name] || task.step_name}</strong><span>{compactMetrics(task.metrics)}</span></div>)}</div></Card><Card><div className="ops-card-title"><RefreshCw size={17} /><h3>门控与深评模型</h3></div><div className="ops-model-grid">{query.data.models.agents.map(agent => <div key={`${agent.agent_name}/${agent.model_profile}`}><strong>{agent.agent_name === 'news_tech_map_gate' ? '技术地图门控' : agent.agent_name === 'news_deep_review' ? '深度评审' : agent.agent_name}</strong><span>{agent.provider} / {agent.model_profile}</span><p>调用 {agent.total} · 成功 {agent.success} · 失败 {agent.failed} · 平均 {agent.avg_latency_ms}ms</p></div>)}</div></Card><Card><div className="ops-card-title"><CheckCircle2 size={17} /><h3>质量审计</h3></div>{query.data.audits.length ? query.data.audits.map(audit => <div className="ops-audit" key={audit.id}><Status value={audit.status} /><strong>{audit.audit_type}</strong><span>{audit.score ?? '—'}</span><p>{audit.summary}</p></div>) : <EmptyState title="暂无质量审计" description="Pipeline 的审计步骤完成后将在这里展示结果。" />}</Card></div>;
}

function Status({ value }: { value: string }) { const good = ['ok', 'success', 'healthy', 'pass', 'completed'].includes(value); const bad = ['failed', 'error', 'unhealthy', 'fail'].includes(value); return <Badge tone={good ? 'green' : bad ? 'red' : value === 'running' ? 'sky' : 'amber'}>{value === 'success' ? '成功' : value === 'running' ? '运行中' : value === 'failed' ? '失败' : ['ok', 'healthy'].includes(value) ? '健康' : value === 'unknown' ? '未知' : value}</Badge>; }
function Loading() { return <div className="news-loading"><div /><div /><div /></div>; }
function formatTime(value?: string) { return value ? value.replace('T', ' ').slice(0, 19) : '—'; }
function compactMetrics(metrics: Record<string, unknown>) { const entries = Object.entries(metrics || {}).filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value)).slice(0, 5); return entries.length ? entries.map(([key, value]) => `${key}: ${String(value)}`).join(' · ') : '暂无指标'; }
