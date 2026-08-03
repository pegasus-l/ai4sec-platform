import { useMemo, useState, useEffect, useRef, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Badge, MetricCard, EmptyState } from '../../components/ui';
import { useToast } from '../../components/Toast';
import { useDrawerStack } from '../../components/DrawerStack';
import {
  fetchToday, fetchLibrary, fetchReproRuns, fetchConversions, fetchClassifyStats,
  fetchDetail, fetchReproTask, startRepro, stopRepro, cleanupRepro, markConversion,
  streamReproLogs, classifyLogLine, stripAnsi,
} from './capabilityQueries';
import type { CapabilityItem, ReproTask, ConversionRecord, CapabilityView } from './capabilityTypes';
import { CapabilityOps, CapabilityOpsQuality, CapabilityOpsRuns } from './CapabilityOps';

const navGroups: Array<{ title: string; items: Array<{ id: CapabilityView; icon: string; title: string }> }> = [
  { title: '能力洞察', items: [
    { id: 'today', icon: '★', title: '今日能力' },
    { id: 'library', icon: '▤', title: '能力库' },
    { id: 'repro', icon: '⚙', title: '复现验证' },
    { id: 'conversion', icon: '↗', title: '能力转化' },
  ]},
  { title: '运营', items: [
    { id: 'ops-overview', icon: '◉', title: '运营概览' },
    { id: 'ops-quality', icon: '◈', title: '质量审计' },
    { id: 'ops-runs', icon: '↻', title: 'Pipeline 运行' },
  ]},
];

const conversionGroups = ['待评估', '待复现', '复现中', '复现成功', '待集成', '持续观察', '已采用'];

interface ConvertFormData { status: string; scenario: string; owner: string; next_action: string; notes: string; }

function sourceNewsScore(payload: CapabilityItem['payload']): number | null {
  const directScore = Number(payload?.source_news_score);
  if (Number.isFinite(directScore) && directScore > 0) return directScore;
  const sourceItem = payload?.source_news_item as Record<string, unknown> | undefined;
  const inheritedScore = Number(sourceItem?.score);
  return Number.isFinite(inheritedScore) && inheritedScore > 0 ? inheritedScore : null;
}

function formatScore(score: number): string {
  return Number.isInteger(score) ? String(score) : score.toFixed(1);
}

export function CapabilityPage() {
  const [view, setView] = useState<CapabilityView>('today');
  const { push } = useDrawerStack();
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: todayData, isLoading: todayLoading } = useQuery({ queryKey: ['cap-today'], queryFn: fetchToday, staleTime: 300_000 });
  const { data: libraryData } = useQuery({ queryKey: ['cap-library'], queryFn: () => fetchLibrary(50), staleTime: 300_000 });
  const { data: reproData } = useQuery({ queryKey: ['cap-repro'], queryFn: fetchReproRuns, staleTime: 1_000, refetchInterval: 5_000 });
  const { data: convData } = useQuery({ queryKey: ['cap-conversions'], queryFn: fetchConversions, staleTime: 300_000 });
  const { data: statsData } = useQuery({ queryKey: ['cap-classify-stats'], queryFn: fetchClassifyStats, staleTime: 300_000 });

  const todayItems = ((todayData as Record<string, unknown> | undefined)?.items ?? []) as CapabilityItem[];
  const libraryItems = ((libraryData as Record<string, unknown> | undefined)?.items ?? []) as CapabilityItem[];
  const reproRuns = ((reproData as Record<string, unknown> | undefined)?.items ?? []) as ReproTask[];
  const conversions = ((convData as Record<string, unknown> | undefined)?.items ?? []) as ConversionRecord[];
  const stats = statsData ?? { total: 0, classified: 0, unclassified: 0, web_count: 0 };

  const viewRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if (viewRef.current) viewRef.current.scrollTop = 0; }, [view]);

  // 【改动 4】抽屉打开时调 fetchDetail 获取完整 payload
  const openDetail = useCallback((item: CapabilityItem) => {
    push({
      title: item.title,
      subtitle: `${item.payload?.source_type ?? ''} · score ${item.score}`,
      render: () => <CapabilityDetailContent itemId={item.id} initialItem={item} onRepro={async () => {
        try {
          const result = await startRepro(item.id, item.payload?.is_web ?? false);
          if (result.skipped && result.demo_url) {
            toast('检测到官方 Demo，无需启动本地复现', 'success');
            window.open(result.demo_url, '_blank', 'noopener');
            return;
          }
          toast('已加入复现队列，正在打开实时工作台', 'success');
          await qc.invalidateQueries({ queryKey: ['cap-repro'] });
          setView('repro');
        }
        catch (e) { toast(`复现失败: ${e}`, 'error'); }
      }} onConvert={async (data: ConvertFormData) => {
        try { await markConversion(item.id, data); toast('已标记转化', 'success'); qc.invalidateQueries({ queryKey: ['cap-conversions'] }); }
        catch (e) { toast(`转化失败: ${e}`, 'error'); }
      }} />,
    });
  }, [push, toast, qc]);

  const openConversion = useCallback((conv: ConversionRecord) => {
    push({
      title: conv.title,
      subtitle: `转化状态: ${conv.status} · 负责人: ${conv.owner || '未分配'}`,
      render: () => <ConversionDetailContent conv={conv} />,
    });
  }, [push]);

  return <main className="main">
    <aside className="ai4sec-sidebar">
      <div className="ai4sec-sidebar-head"><div className="label"><span className="dot" /><span>能力洞察</span></div><h2>前沿项目能力化</h2><p>从资讯筛选可复现项目，到自动复现验证，再到能力转化落地。</p></div>
      <div className="domain-switcher">
        <button className="domain-btn active" type="button"><span className="domain-icon">A/S</span><span className="domain-main"><strong>AI for SEC</strong><span>AI 用于安全能力</span></span><span className="domain-tag">CAP</span></button>
      </div>
      <nav className="nav-scroll">{navGroups.map(group => <div className="nav-group" key={group.title}><div className="group-title">{group.title}</div>{group.items.map(item => <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} onClick={() => setView(item.id)}><span className="nav-left"><span className="nav-ico">{item.icon}</span><span className="nav-text"><b>{item.title}</b></span></span>{item.id === 'today' && todayItems.length > 0 && <span className="badge badge-green">{todayItems.length}</span>}{item.id === 'library' && libraryItems.length > 0 && <span className="badge badge-sky">{libraryItems.length}</span>}{item.id === 'repro' && reproRuns.length > 0 && <span className="badge badge-amber">{reproRuns.length}</span>}{item.id === 'conversion' && conversions.length > 0 && <span className="badge badge-violet">{conversions.length}</span>}</button>)}</div>)}</nav>
      <div className="ai4sec-sidebar-note">能力洞察不重复资讯流，而是把前沿论文和开源项目推进到评分、复现和能力转化。能力详情从今日能力、能力库、复现验证或能力转化点击进入。</div>
    </aside>
    <section className="content">
      <section className="content-head">
        <div className="content-title"><span className="label">{navGroups.flatMap(g => g.items).find(i => i.id === view)?.title ?? '能力洞察'}</span><h1>{heroTitle(view)}</h1><p>{heroCopy(view)}</p></div>
        <div className="head-actions"><label className="search"><span>⌕</span><input placeholder="搜索能力 / 仓库 / 技术点" onChange={() => {}} /></label><button className="btn" onClick={() => qc.invalidateQueries({ queryKey: ['cap-'] })}>刷新数据</button></div>
      </section>
      <div className="content-body view" ref={viewRef}>
        {todayLoading && view === 'today' && <EmptyState title="正在加载" description="从 /api/capabilities/today 拉取数据。" />}
        {view === 'today' && <CapabilityToday items={todayItems} stats={stats} openDetail={openDetail} />}
        {view === 'library' && <CapabilityLibrary items={libraryItems} openDetail={openDetail} />}
        {view === 'repro' && <CapabilityRepro runs={reproRuns} openDetail={openDetail} items={libraryItems} />}
        {view === 'conversion' && <CapabilityConversion conversions={conversions} openConversion={openConversion} />}
        {view === 'ops-overview' && <CapabilityOps />}
        {view === 'ops-quality' && <CapabilityOpsQuality />}
        {view === 'ops-runs' && <CapabilityOpsRuns />}
      </div>
    </section>
  </main>;
}

function heroTitle(view: CapabilityView): string {
  return { today: '今日能力推荐', library: '能力库', repro: '复现验证', conversion: '能力转化', 'ops-overview': '运营概览', 'ops-quality': '质量审计', 'ops-runs': 'Pipeline 运行' }[view];
}
function heroCopy(view: CapabilityView): string {
  return {
    today: '今天最值得复现/转化的项目或论文，基于多维度评分筛选。',
    library: '已评分、已分类、可检索的能力资产。',
    repro: '自动复现状态、实时日志、环境和产物。',
    conversion: '有状态、有目的的收藏 / 专题，推进能力落地。',
    'ops-overview': '运营数据概览、复现失败审计、能力卡缺字段审计、Web 分类统计。',
    'ops-quality': '复现失败详情、能力卡缺字段详情、Web 分类统计。',
    'ops-runs': '能力洞察 Pipeline 运行历史、步骤详情、产物列表。',
  }[view];
}

// ========== 今日能力 ==========
function CapabilityToday({ items, stats, openDetail }: { items: CapabilityItem[]; stats: { total: number; classified: number; unclassified: number; web_count: number }; openDetail: (item: CapabilityItem) => void }) {
  const { toast } = useToast();
  const [viewMode, setViewMode] = useState<'推荐' | '高可复现' | '高应用潜力' | '需人工判断'>('推荐');

  const filtered = useMemo(() => {
    if (viewMode === '高可复现') return items.filter(i => i.payload?.repro_status === 'candidate' || i.payload?.code_url);
    if (viewMode === '高应用潜力') return items.filter(i => (i.payload?.application_scenarios ?? []).length > 0);
    if (viewMode === '需人工判断') return items.filter(i => i.payload?.repro_status === 'no_code' || !i.payload?.code_url);
    return items;
  }, [items, viewMode]);

  return <div className="grid">
    <div className="grid cols-4">
      <MetricCard label="今日能力" value={items.length} hint="高潜力候选" tone="green" />
      <MetricCard label="能力库" value={stats.total} hint="已评分能力资产" tone="sky" />
      <MetricCard label="Web 项目" value={stats.web_count} hint="自带 Web 界面" tone="amber" />
      <MetricCard label="未分类" value={stats.unclassified} hint="待 Web 分类" tone="violet" />
    </div>
    <div className="view-switch">
      {(['推荐', '高可复现', '高应用潜力', '需人工判断'] as const).map(v => <span key={v} className={`view-pill ${viewMode === v ? 'active' : ''}`} onClick={() => setViewMode(v)}>{v}</span>)}
    </div>
    <div className="asis-list">
      {filtered.length === 0 && <EmptyState title="暂无能力候选" description="先跑 news.ai_for_sec_local_raw_import + capabilities.from_news_pipeline" />}
      {filtered.map((item, i) => <CapabilityCard key={item.id} item={item} rank={i + 1} onClick={() => openDetail(item)} onRepro={async () => {
        try { await startRepro(item.id, item.payload?.is_web ?? false); toast('已加入复现队列', 'success'); }
        catch (e) { toast(`复现失败: ${e}`, 'error'); }
      }} />)}
    </div>
  </div>;
}

function CapabilityCard({ item, rank, onClick }: { item: CapabilityItem; rank: number; onClick: () => void; onRepro: () => void }) {
  const p = item.payload ?? {};
  const newsScore = sourceNewsScore(p);
  const sourceType = p.source_type || (item.source_url?.includes('github.com') ? 'github' : 'arxiv');
  const reproTag = p.repro_status === 'candidate' ? 'green' : p.repro_status === 'in_progress' ? 'sky' : p.repro_status === 'no_code' ? 'slate' : 'amber';
  const reproText = { candidate: '可复现', in_progress: '复现中', no_code: '无代码', success: '已复现', failed: '复现失败' }[p.repro_status ?? ''] ?? p.repro_status;
  return <div className="asis-card clickable" onClick={onClick}>
    <div className="rank">{rank}</div>
    <div>
      <h4>{p.display_theme || p.one_liner || item.title}</h4>
      <p>{p.overview || p.one_liner || item.summary}</p>
      <div className="badges">
        <Badge tone={sourceType === 'github' ? 'sky' : 'violet'}>{sourceType}</Badge>
        {p.capability_type && <Badge tone="green">{p.capability_type}</Badge>}
        <Badge tone={reproTag as 'green' | 'sky' | 'slate' | 'amber'}>{reproText}</Badge>
        {p.demo_url ? <Badge tone="green">官方 Demo</Badge> : p.is_web ? <Badge tone="amber">Web{p.web_framework ? `:${p.web_framework}` : ''}</Badge> : <Badge tone="slate">非Web</Badge>}
      </div>
    </div>
    <div style={{ display: 'grid', gap: 6, justifyItems: 'end' }}>
      <div className="score-ring" title="能力综合评分（1–5）">{item.score}</div>
      {newsScore !== null && <span className="small muted" title="来源资讯洞察评分">资讯 {formatScore(newsScore)}</span>}
    </div>
  </div>;
}

// ========== 能力库（改动 1: 4 个视图 + 改动 3: classifyBatch 按钮）==========
function CapabilityLibrary({ items, openDetail }: { items: CapabilityItem[]; openDetail: (item: CapabilityItem) => void }) {
  const [viewMode, setViewMode] = useState<'列表视图' | '能力分类' | '应用场景' | '工程可用性'>('列表视图');

  // 【改动 1】能力分类视图：按 capability_type 分组
  const typeGroups = useMemo(() => {
    const g: Record<string, CapabilityItem[]> = {};
    items.forEach(item => { const t = item.payload?.capability_type || '未分类'; (g[t] ??= []).push(item); });
    return g;
  }, [items]);

  // 【改动 1】应用场景视图：按 application_scenarios 分组
  const scenarioGroups = useMemo(() => {
    const g: Record<string, CapabilityItem[]> = {};
    items.forEach(item => { (item.payload?.application_scenarios ?? ['未标注']).forEach(s => { (g[s] ??= []).push(item); }); });
    return g;
  }, [items]);

  const engineeringGroups = useMemo(() => ({
    '官方 Demo': items.filter(i => Boolean(i.payload?.demo_url)),
    '完整复现': items.filter(i => !i.payload?.demo_url && i.payload?.repro_status === 'success'),
    '部分复现': items.filter(i => !i.payload?.demo_url && i.payload?.repro_status === 'partial'),
    '复现中': items.filter(i => !i.payload?.demo_url && i.payload?.repro_status === 'in_progress'),
    '待 Web 复现': items.filter(i => !i.payload?.demo_url && Boolean(i.payload?.is_web) && ['candidate', 'no_code', undefined].includes(i.payload?.repro_status)),
    '待命令行验证': items.filter(i => !i.payload?.demo_url && !i.payload?.is_web && ['candidate', 'no_code', undefined].includes(i.payload?.repro_status)),
    '复现失败': items.filter(i => !i.payload?.demo_url && i.payload?.repro_status === 'failed'),
  }), [items]);

  return <div className="grid">
    <div className="view-switch">
      {(['列表视图', '能力分类', '应用场景', '工程可用性'] as const).map(v => <span key={v} className={`view-pill ${viewMode === v ? 'active' : ''}`} onClick={() => setViewMode(v)}>{v}</span>)}
    </div>
    {items.length === 0 && <EmptyState title="能力库为空" description="先跑 capabilities.from_news_pipeline 生成能力卡" />}

    {/* 列表视图 */}
    {items.length > 0 && viewMode === '列表视图' && <div className="table-card"><table className="data-table"><thead><tr><th>能力</th><th>概述</th><th>能力评分</th><th>资讯洞察</th><th>标签</th></tr></thead><tbody>
      {items.map(item => { const p = item.payload ?? {}; const st = p.source_type || (item.source_url?.includes('github.com') ? 'github' : 'arxiv'); const ov = p.overview || p.one_liner || ''; return <tr key={item.id} className="clickable" onClick={() => openDetail(item)}>
        <td><div className="table-title">{item.title}</div><div className="table-sub">{st}</div></td>
        <td style={{maxWidth: '320px'}} className="small muted">{ov.slice(0, 120)}{ov.length > 120 ? '…' : ''}</td>
        <td><div className="score-ring">{item.score}</div></td>
        <td>{sourceNewsScore(p) !== null ? <Badge tone="sky">{formatScore(sourceNewsScore(p)!)}</Badge> : <span className="muted">—</span>}</td>
        <td><div className="badges">{p.capability_type && <Badge tone="green">{p.capability_type}</Badge>}<Badge tone={p.repro_status === 'candidate' ? 'green' : 'amber'}>{p.repro_status ?? '未知'}</Badge>{p.is_web ? <Badge tone="amber">Web</Badge> : <Badge tone="slate">非Web</Badge>}</div></td>
      </tr>; })}
    </tbody></table></div>}

    {/* 能力分类视图 */}
    {items.length > 0 && viewMode === '能力分类' && Object.entries(typeGroups).map(([type, groupItems]) => (
      <div className="panel" key={type}>
        <div className="panel-head"><h3>{type}</h3><span>{groupItems.length} 个</span></div>
        <div className="panel-body"><div className="asis-list">
          {groupItems.map((item, i) => <CapabilityCard key={item.id} item={item} rank={i + 1} onClick={() => openDetail(item)} onRepro={() => {}} />)}
        </div></div>
      </div>
    ))}

    {/* 应用场景视图 */}
    {items.length > 0 && viewMode === '应用场景' && Object.entries(scenarioGroups).map(([scenario, groupItems]) => (
      <div className="panel" key={scenario}>
        <div className="panel-head"><h3>{scenario}</h3><span>{groupItems.length} 个</span></div>
        <div className="panel-body"><div className="asis-list">
          {groupItems.map((item, i) => <CapabilityCard key={item.id} item={item} rank={i + 1} onClick={() => openDetail(item)} onRepro={() => {}} />)}
        </div></div>
      </div>
    ))}

    {/* 工程可用性视图 */}
    {items.length > 0 && viewMode === '工程可用性' && <div className="grid cols-2">
      {Object.entries(engineeringGroups).map(([label, groupItems]) => (
        <div className="panel" key={label}>
          <div className="panel-head"><h3>{label}</h3><span>{groupItems.length} 个</span></div>
          <div className="panel-body"><div className="asis-list">
            {groupItems.length === 0 && <div className="empty-hint">暂无</div>}
            {groupItems.map((item, i) => <CapabilityCard key={item.id} item={item} rank={i + 1} onClick={() => openDetail(item)} onRepro={() => {}} />)}
          </div></div>
        </div>
      ))}
    </div>}
  </div>;
}

// ========== 复现验证 ==========
function CapabilityRepro({ runs, items, openDetail }: { runs: ReproTask[]; items: CapabilityItem[]; openDetail: (item: CapabilityItem) => void }) {
  const [selectedTaskId, setSelectedTaskId] = useState<number | null>(null);
  useEffect(() => {
    if (runs.length > 0 && (selectedTaskId === null || !runs.some(run => run.id === selectedTaskId))) {
      setSelectedTaskId(runs[0].id);
    }
  }, [runs, selectedTaskId]);
  const selected = runs.find(run => run.id === selectedTaskId) ?? runs[0];
  const capabilityItem = items.find(i => i.id === selected?.item_id);
  const runningCount = runs.filter(run => run.status === 'running' || run.status === 'queued').length;
  const successCount = runs.filter(run => run.status === 'success' || run.status === 'partial').length;
  const failedCount = runs.filter(run => run.status === 'failed' || run.status === 'timeout').length;

  return <div className="grid">
    {runs.length === 0 && <EmptyState title="暂无复现任务" description="从今日能力或能力库点击「加入复现」触发" />}
    {runs.length > 0 && <>
      <div className="repro-metrics">
        <div><span>全部任务</span><b>{runs.length}</b></div>
        <div><span>正在复现</span><b className="repro-running">{runningCount}</b></div>
        <div><span>复现成功</span><b className="repro-success">{successCount}</b></div>
        <div><span>失败 / 超时</span><b className="repro-failed">{failedCount}</b></div>
      </div>
      <div className="repro-workbench">
        <div className="panel repro-task-panel">
          <div className="panel-head"><h3>任务队列 ({runs.length})</h3><span>{runningCount > 0 ? '实时更新中' : '历史任务'}</span></div>
          <div className="panel-body repro-task-list">
            {runs.map((run, index) => <button type="button" key={run.id} className={`repro-task ${run.id === selected?.id ? 'active' : ''}`} onClick={() => setSelectedTaskId(run.id)}>
              <span className={`repro-status-dot status-${run.status}`} />
              <span className="repro-task-main">
                <strong>{run.title || run.repo_url?.split('/').filter(Boolean).slice(-1)[0] || `task-${run.id}`}</strong>
                <small>#{run.id} · {run.trigger || 'manual'} · {formatReproTime(run.created_at)}</small>
              </span>
              <span className={`repro-status status-${run.status}`}>{reproStatusLabel(run.status)}</span>
              {index === 0 && (run.status === 'running' || run.status === 'queued') && <span className="repro-live">LIVE</span>}
            </button>)}
          </div>
        </div>
        <div className="panel repro-detail-panel">
          <div className="panel-head"><h3>复现控制台</h3><span>实时日志 · 结构化报告 · Web 验证</span></div>
          <div className="panel-body">
            {selected && <ReproDetailContent task={selected} capabilityItem={capabilityItem} openDetail={openDetail} />}
          </div>
        </div>
      </div>
    </>}
  </div>;
}

function ReproDetailContent({ task, capabilityItem, openDetail }: { task: ReproTask; capabilityItem?: CapabilityItem; openDetail: (item: CapabilityItem) => void }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [logs, setLogs] = useState<{ line: string; kind: string }[]>([]);
  const [streaming, setStreaming] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const cleanupRef = useRef<(() => void) | null>(null);
  const { data: taskDetail } = useQuery({
    queryKey: ['cap-repro-task', task.id],
    queryFn: () => fetchReproTask(task.id),
    refetchInterval: task.status === 'running' || task.status === 'queued' ? 2_000 : false,
  });
  const currentTask = taskDetail ?? task;
  const [liveStatus, setLiveStatus] = useState(currentTask.status);
  const [liveReport, setLiveReport] = useState(currentTask.report ?? null);

  useEffect(() => {
    setLogs([]);
    setLiveStatus(currentTask.status);
    setLiveReport(currentTask.report ?? null);
  }, [currentTask.id]);

  useEffect(() => {
    setLiveStatus(currentTask.status);
    if (currentTask.report) setLiveReport(currentTask.report);
  }, [currentTask.status, currentTask.report]);

  useEffect(() => {
    if (currentTask.status === 'running' || currentTask.status === 'queued') {
      setStreaming(true);
      setLogs([]);
      cleanupRef.current = streamReproLogs(currentTask.id,
        (line, kind) => setLogs(prev => [...prev, { line, kind }]),
        (status, report) => {
          setLiveStatus(status);
          if (report) setLiveReport(report as NonNullable<ReproTask['report']>);
          if (!['running', 'queued'].includes(status)) {
            setStreaming(false);
            qc.invalidateQueries({ queryKey: ['cap-repro'] });
            qc.invalidateQueries({ queryKey: ['cap-repro-task', currentTask.id] });
            qc.invalidateQueries({ queryKey: ['cap-library'] });
          }
        },
        () => setStreaming(false)
      );
      return () => { cleanupRef.current?.(); };
    }
  }, [currentTask.id, currentTask.status, qc]);

  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [logs]);

  const report = liveReport ?? currentTask.report ?? capabilityItem?.payload?.repro_report;
  const p = capabilityItem?.payload ?? {};
  const displayedLogs = streaming ? logs : (currentTask.log_excerpt || currentTask.result || '').split('\n').filter(Boolean).map(line => ({ line: stripAnsi(line), kind: classifyLogLine(line) }));

  return <div className="repro-console">
    <div className="repro-console-head">
      <div><span className={`repro-status status-${liveStatus}`}>{reproStatusLabel(liveStatus)}</span><strong>{currentTask.repo_url?.split('/').filter(Boolean).slice(-1)[0]}</strong></div>
      <div className="repro-meta">任务 #{currentTask.id}{currentTask.web_port ? ` · Web ${currentTask.web_port}` : ''}</div>
    </div>
    <div className="repro-actions">
      {p.demo_url && <a className="btn primary" href={p.demo_url} target="_blank" rel="noreferrer">打开官方 Demo ↗</a>}
      {!p.demo_url && currentTask.web_url && report?.web_started && <a className="btn primary" href={currentTask.web_url} target="_blank" rel="noreferrer">打开 Web 验证 ↗</a>}
      {!p.demo_url && <button className="btn primary" onClick={async () => { if (capabilityItem) { try { await startRepro(capabilityItem.id, p.is_web ?? false); toast('已重跑复现', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } catch (e) { toast(`重跑失败: ${e}`, 'error'); } } }}>重跑</button>}
      {['running', 'queued'].includes(liveStatus) && <button className="btn" onClick={async () => { try { await stopRepro(currentTask.id); toast('已停止', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } catch (e) { toast(`停止失败: ${e}`, 'error'); } }}>停止</button>}
      <button className="btn" onClick={async () => { try { await cleanupRepro(currentTask.id); toast('已清理', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } catch (e) { toast(`清理失败: ${e}`, 'error'); } }}>清理</button>
      {capabilityItem && <button className="btn" onClick={() => openDetail(capabilityItem)}>查看能力详情</button>}
    </div>
    <section className="repro-section">
      <div className="repro-section-title"><span>执行日志</span><small>{streaming ? 'SSE LIVE' : `${displayedLogs.length} 行摘要`}</small></div>
      <div className="log-stream" ref={logRef}>{displayedLogs.map((log, index) => <div key={`${index}-${log.line}`} className={`log-line log-${log.kind}`}>{log.line}</div>)}{displayedLogs.length === 0 && <div className="muted small">{liveStatus === 'queued' ? '任务已排队，等待复现调度…' : '等待日志输出…'}</div>}</div>
    </section>
    {report && <>
      <section className="repro-section">
        <div className="repro-section-title"><span>复现结论</span><small>{report.level || report.web_framework || report.project_type || '自动报告'}</small></div>
        <div className={`repro-summary ${report.status === 'success' ? 'success' : report.status === 'partial' ? 'partial' : 'failed'}`}><strong>{report.summary || '暂无摘要'}</strong>{report.verify && <p>验证：{report.verify}</p>}</div>
        <div className="field-grid repro-fields">
          <div className="cap-field"><span>报告状态</span><b>{reproStatusLabel(report.status)}</b></div>
          <div className="cap-field"><span>项目类型</span><b>{report.web_framework || report.project_type || '-'}</b></div>
          <div className="cap-field"><span>Web 启动</span><b>{report.is_web ? (report.web_started ? '已启动并验证' : '未启动') : '非 Web 项目'}</b></div>
          <div className="cap-field"><span>启动命令</span><code>{report.start_command || '-'}</code></div>
        </div>
      </section>
      {report.is_web && <section className="repro-section">
        <div className="repro-section-title"><span>核心可用性验收</span><small>{report.core_workflow?.verified ? '已通过' : '未通过'}</small></div>
        <div className={`repro-summary ${report.core_workflow?.verified ? 'success' : 'partial'}`}>
          <strong>{report.core_workflow?.goal || '未定义核心用户闭环'}</strong>
          <p>运行模式：{report.core_workflow?.mode === 'real' ? '真实模式' : report.core_workflow?.mode === 'mock' ? 'Mock 模式' : '未验证'}</p>
          <p>验收结果：{report.core_workflow?.result || '未执行核心业务链'}</p>
          {(report.core_workflow?.evidence?.length ?? 0) > 0 && <p>证据：{report.core_workflow?.evidence?.join('；')}</p>}
        </div>
        {(report.acceptance_issues?.length ?? 0) > 0 && <div className="repro-findings">
          {(report.acceptance_issues ?? []).map((issue, index) => <div className="blocker" key={`acceptance-${index}`}>自动验收：{issue}</div>)}
        </div>}
      </section>}
      {report.usage && Object.keys(report.usage).length > 0 && <section className="repro-section">
        <div className="repro-section-title"><span>使用说明</span><small>面向使用者</small></div>
        <div className="repro-usage">
          {report.usage.what && <div><span>能力说明</span><p>{report.usage.what}</p></div>}
          {report.usage.how_to_use && <div><span>如何使用</span><p>{report.usage.how_to_use}</p></div>}
          {report.usage.prerequisites && <div><span>前置条件</span><p>{report.usage.prerequisites}</p></div>}
          {report.usage.limitations && <div><span>当前限制</span><p>{report.usage.limitations}</p></div>}
        </div>
      </section>}
      {report.steps && report.steps.length > 0 && <section className="repro-section">
        <div className="repro-section-title"><span>关键步骤</span><small>{report.steps.length} 步</small></div>
        <div className="repro-step-list">{report.steps.map((step, index) => <div className={step.ok ? 'ok' : 'failed'} key={`${index}-${step.cmd}`}><span>{step.ok ? '✓' : '✗'}</span><code>{step.cmd}</code>{step.note && <p>{step.note}</p>}</div>)}</div>
      </section>}
      {((report.blockers?.length ?? 0) > 0 || (report.gotchas?.length ?? 0) > 0) && <section className="repro-section repro-findings">
        {(report.blockers ?? []).map((blocker, index) => <div className="blocker" key={`blocker-${index}`}>阻塞：{blocker}</div>)}
        {(report.gotchas ?? []).map((gotcha, index) => <div className="gotcha" key={`gotcha-${index}`}>注意：{gotcha}</div>)}
      </section>}
    </>}
  </div>;
}

function reproStatusLabel(status: string): string {
  return { queued: '排队中', running: '复现中', success: '复现成功', partial: '部分成功', failed: '复现失败', stopped: '已停止', timeout: '已超时', cleaned: '已清理' }[status] ?? status;
}

function formatReproTime(value?: string): string {
  if (!value) return '时间未知';
  return value.replace('T', ' ').replace('Z', '').slice(0, 16);
}

// ========== 能力转化 ==========
function CapabilityConversion({ conversions, openConversion }: { conversions: ConversionRecord[]; openConversion: (conv: ConversionRecord) => void }) {
  return <div className="grid">
    {conversions.length === 0 && <EmptyState title="暂无转化记录" description="从今日能力或能力库点击「加入转化」标记项目" />}
    {conversions.length > 0 && <div className="kanban">{conversionGroups.map(group => <div className="kanban-col" key={group}>
      <div className="kanban-head"><span>{group}</span><Badge tone="slate">{conversions.filter(c => c.status === group).length}</Badge></div>
      {conversions.filter(c => c.status === group).map(c => <div key={c.id} className="mini-card clickable" onClick={() => openConversion(c)}>
        <b>{c.title}</b><p>{c.next_action}</p>
        <div className="badges"><Badge tone="sky">{c.scenario}</Badge>{c.owner && <Badge tone="violet">{c.owner}</Badge>}</div>
      </div>)}
      {conversions.filter(c => c.status === group).length === 0 && <div className="empty-hint">暂无卡片</div>}
    </div>)}</div>}
  </div>;
}

// ========== 能力详情抽屉内容（改动 2: 转化表单 + 改动 4: fetchDetail）==========
function CapabilityDetailContent({ itemId, initialItem, onRepro, onConvert }: { itemId: number; initialItem: CapabilityItem; onRepro: () => void; onConvert: (data: ConvertFormData) => Promise<void> }) {
  // 【改动 4】调 fetchDetail 获取完整 payload
  const { data: item } = useQuery({
    queryKey: ['cap-detail', itemId],
    queryFn: () => fetchDetail(itemId),
    initialData: initialItem,
    staleTime: 0,
  });
  const p = item?.payload ?? initialItem.payload ?? {};
  const newsScore = sourceNewsScore(p);

  // 【改动 2】转化表单状态
  const [showConvertForm, setShowConvertForm] = useState(false);
  const [convertData, setConvertData] = useState<ConvertFormData>({ status: '持续观察', scenario: '', owner: '', next_action: '', notes: '' });
  const [submitting, setSubmitting] = useState(false);

  const handleConvert = async () => {
    setSubmitting(true);
    await onConvert(convertData);
    setSubmitting(false);
    setShowConvertForm(false);
  };

  return <div className="grid">
    {/* 能力评分（LLM 自然语言理由） */}
    <div className="drawer-section">
      <h3>能力评分</h3>
      <div className="split" style={{ alignItems: 'center' }}>
        <div className="score-ring">{item?.score ?? initialItem.score}</div>
        <div style={{ flex: 1 }}>
          {p.score_reason ? <p>{p.score_reason}</p> : <p className="small muted">基于多维度综合评分</p>}
        </div>
      </div>
    </div>

    {newsScore !== null && <div className="drawer-section">
      <h3>来源资讯洞察评分</h3>
      <div className="split" style={{ alignItems: 'center' }}>
        <div className="score-ring">{formatScore(newsScore)}</div>
        <p style={{ flex: 1 }}>该项目在资讯洞察阶段的原始综合评分；与上方能力综合评分独立，用于保留来源热度与价值判断。</p>
      </div>
    </div>}

    {/* LLM 评估 */}
    {p.overview && <div className="drawer-section"><h3>项目概述</h3><p>{p.overview}</p></div>}
    {p.security_value && <div className="drawer-section"><h3>安全价值</h3><p>{p.security_value}</p></div>}
    {p.reproducibility_assessment && <div className="drawer-section"><h3>复现可行性</h3><p>{p.reproducibility_assessment}</p></div>}
    {p.code_quality && <div className="drawer-section"><h3>代码质量</h3><p>{p.code_quality}</p></div>}
    {p.application_advice && <div className="drawer-section"><h3>应用建议</h3><p>{p.application_advice}</p></div>}

    {/* 项目信息（合并：信息 + 宣传 + 亮点 + 摘要） */}
    <div className="drawer-section">
      <h3>项目信息</h3>
      {p.display_work_name && <p><b>工作名:</b> {p.display_work_name}</p>}
      <p><b>技术定位:</b> {p.display_theme || item?.summary || '—'}</p>
      {(item?.title || initialItem.title) !== (p.display_theme || '') && <p className="small muted">原始标题: {item?.title || initialItem.title}</p>}
      {(item?.source_url || initialItem.source_url) && <p style={{ marginTop: 4 }}><a href={item?.source_url || initialItem.source_url} target="_blank" rel="noopener" style={{ color: 'var(--sky)' }}>🔗 {item?.source_url || initialItem.source_url}</a></p>}
      {p.demo_url && <p><a href={p.demo_url} target="_blank" rel="noopener" style={{ color: 'var(--sky)' }}>🔗 在线 Demo</a></p>}
      <p style={{ marginTop: 10 }}><b>宣传一句话:</b> {p.one_liner || '—'}</p>
      {p.highlight && <p><b>亮点:</b> <span style={{ color: 'var(--green)' }}>{p.highlight}</span></p>}
      <p style={{ marginTop: 10 }}><b>中文摘要:</b> {p.summary || item?.summary || initialItem.summary || '—'}</p>
    </div>

    {/* 技术点 */}
    {p.tech_points && p.tech_points.length > 0 && <div className="drawer-section"><h3>技术点 · {p.tech_points.length} 项</h3><div className="badges">{p.tech_points.map((t: string) => <Badge key={t} tone="sky">{t}</Badge>)}</div></div>}

    {/* 能力评估 */}
    <div className="drawer-section"><h3>能力评估</h3><div className="badges">{p.capability_type && <Badge tone="green">{p.capability_type}</Badge>}{p.application_scenarios && p.application_scenarios.length > 0 && p.application_scenarios.map((s: string) => <Badge key={s} tone="violet">{s}</Badge>)}</div></div>

    {/* 复现 & 转化 */}
    {p.demo_url && <div className="drawer-section"><h3>官方在线演示</h3><p style={{ color: 'var(--green)' }}>项目已提供官方 Demo，按复现策略直接使用官方环境，不启动本地容器。</p><p><a href={p.demo_url} target="_blank" rel="noopener" style={{ color: 'var(--sky)' }}>{p.demo_url}</a></p></div>}
    {!p.demo_url && p.repro_summary && <div className="drawer-section"><h3>复现摘要</h3><p style={{ color: 'var(--green)' }}>{p.repro_summary}</p></div>}
    <div className="drawer-section"><h3>复现 & 转化</h3><div className="badges"><Badge tone={p.repro_status === 'candidate' ? 'green' : 'amber'}>{p.repro_status ?? '未知'}</Badge><Badge tone="violet">{p.conversion_status ?? '待评估'}</Badge>{p.is_web ? <Badge tone="amber">Web{p.web_framework ? `:${p.web_framework}` : ''}</Badge> : <Badge tone="slate">非Web</Badge>}</div></div>

    {/* 使用说明 */}
    {p.usage && Object.keys(p.usage).length > 0 && <div className="drawer-section"><h3>使用说明</h3><p><b>是什么:</b> {p.usage.what ?? ''}</p><p><b>怎么用:</b> {p.usage.how_to_use ?? ''}</p>{p.usage.prerequisites && <p><b>前提:</b> {p.usage.prerequisites}</p>}{p.usage.limitations && <p><b>限制:</b> {p.usage.limitations}</p>}</div>}

    {/* 【改动 2】转化表单 */}
    {showConvertForm && <div className="drawer-section">
      <h3>转化信息</h3>
      <div style={{ display: 'grid', gap: 10 }}>
        <div>
          <span className="muted small">状态</span>
          <select className="select" style={{ width: '100%', marginTop: 4 }} value={convertData.status} onChange={e => setConvertData(d => ({ ...d, status: e.target.value }))}>
            <option value="待评估">待评估</option>
            <option value="待复现">待复现</option>
            <option value="复现中">复现中</option>
            <option value="持续观察">持续观察</option>
            <option value="已采用">已采用</option>
          </select>
        </div>
        <div>
          <span className="muted small">应用场景</span>
          <input className="search" style={{ width: '100%', marginTop: 4 }} placeholder="如：代码审计 / Agent 工作流" value={convertData.scenario} onChange={e => setConvertData(d => ({ ...d, scenario: e.target.value }))} />
        </div>
        <div>
          <span className="muted small">负责人</span>
          <input className="search" style={{ width: '100%', marginTop: 4 }} placeholder="分配负责人" value={convertData.owner} onChange={e => setConvertData(d => ({ ...d, owner: e.target.value }))} />
        </div>
        <div>
          <span className="muted small">下一步动作</span>
          <input className="search" style={{ width: '100%', marginTop: 4 }} placeholder="如：接入 CI pipeline" value={convertData.next_action} onChange={e => setConvertData(d => ({ ...d, next_action: e.target.value }))} />
        </div>
        <div>
          <span className="muted small">备注</span>
          <input className="search" style={{ width: '100%', marginTop: 4 }} placeholder="补充说明" value={convertData.notes} onChange={e => setConvertData(d => ({ ...d, notes: e.target.value }))} />
        </div>
      </div>
    </div>}

    <div className="drawer-actions">
      {p.demo_url && <a className="pill-button primary" href={p.demo_url} target="_blank" rel="noopener">打开官方 Demo</a>}
      {!p.demo_url && p.is_web && <button className="pill-button primary" onClick={onRepro}>加入复现</button>}
      {!showConvertForm && <button className="pill-button" onClick={() => setShowConvertForm(true)}>加入转化</button>}
      {showConvertForm && <button className="pill-button primary" onClick={handleConvert} disabled={submitting}>{submitting ? '提交中…' : '确认转化'}</button>}
    </div>
  </div>;
}

function ConversionDetailContent({ conv }: { conv: ConversionRecord }) {
  return <div className="grid">
    <div className="drawer-section"><h3>场景</h3><p>{conv.scenario}</p></div>
    <div className="drawer-section"><h3>下一步</h3><p style={{ color: 'var(--green)' }}>{conv.next_action}</p></div>
    <div className="drawer-section"><h3>负责人</h3><p>{conv.owner || '未分配'}</p></div>
    {conv.notes && <div className="drawer-section"><h3>备注</h3><p>{conv.notes}</p></div>}
  </div>;
}
