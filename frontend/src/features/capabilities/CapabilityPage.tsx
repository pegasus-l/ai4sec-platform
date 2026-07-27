import { useMemo, useState, useEffect, useRef, useCallback } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Badge, MetricCard, EmptyState } from '../../components/ui';
import { useToast } from '../../components/Toast';
import { useDrawerStack } from '../../components/DrawerStack';
import {
  fetchToday, fetchLibrary, fetchReproRuns, fetchConversions, fetchClassifyStats,
  fetchDetail, startRepro, stopRepro, cleanupRepro, markConversion,
  streamReproLogs, classifyLogLine,
} from './capabilityQueries';
import type { CapabilityItem, ReproTask, ConversionRecord, CapabilityView } from './capabilityTypes';
import { CapabilityOps, CapabilityOpsQuality, CapabilityOpsRuns } from './CapabilityOps';
import '../../styles/capability.css';

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

export function CapabilityPage() {
  const [view, setView] = useState<CapabilityView>('today');
  const { push } = useDrawerStack();
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: todayData, isLoading: todayLoading } = useQuery({ queryKey: ['cap-today'], queryFn: fetchToday, staleTime: 300_000 });
  const { data: libraryData } = useQuery({ queryKey: ['cap-library'], queryFn: () => fetchLibrary(50), staleTime: 300_000 });
  const { data: reproData } = useQuery({ queryKey: ['cap-repro'], queryFn: fetchReproRuns, staleTime: 300_000 });
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
        try { await startRepro(item.id, item.payload?.is_web ?? false); toast('已加入复现队列', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); }
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
    <aside className="sidebar">
      <div className="sidebar-head"><div className="label"><span className="dot" /><span>能力洞察</span></div><h2>前沿项目能力化</h2><p>从资讯筛选可复现项目，到自动复现验证，再到能力转化落地。</p></div>
      <div className="domain-switcher">
        <button className="domain-btn active" type="button"><span className="domain-icon">A/S</span><span className="domain-main"><strong>AI for SEC</strong><span>AI 用于安全能力</span></span><span className="domain-tag">CAP</span></button>
      </div>
      <nav className="nav-scroll">{navGroups.map(group => <div className="nav-group" key={group.title}><div className="group-title">{group.title}</div>{group.items.map(item => <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} onClick={() => setView(item.id)}><span className="nav-left"><span className="nav-ico">{item.icon}</span><span className="nav-text"><b>{item.title}</b></span></span>{item.id === 'today' && todayItems.length > 0 && <span className="badge badge-green">{todayItems.length}</span>}{item.id === 'library' && libraryItems.length > 0 && <span className="badge badge-sky">{libraryItems.length}</span>}{item.id === 'repro' && reproRuns.length > 0 && <span className="badge badge-amber">{reproRuns.length}</span>}{item.id === 'conversion' && conversions.length > 0 && <span className="badge badge-violet">{conversions.length}</span>}</button>)}</div>)}</nav>
      <div className="sidebar-note">能力洞察不重复资讯流，而是把前沿论文和开源项目推进到评分、复现和能力转化。能力详情从今日能力、能力库、复现验证或能力转化点击进入。</div>
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
  const sourceType = p.source_type || (item.source_url?.includes('github.com') ? 'github' : 'arxiv');
  const reproTag = p.repro_status === 'candidate' ? 'green' : p.repro_status === 'in_progress' ? 'sky' : p.repro_status === 'no_code' ? 'slate' : 'amber';
  const reproText = { candidate: '可复现', in_progress: '复现中', no_code: '无代码', success: '已复现', failed: '复现失败' }[p.repro_status ?? ''] ?? p.repro_status;
  return <div className="asis-card clickable" onClick={onClick}>
    <div className="rank">{rank}</div>
    <div>
      <h4>{item.title}</h4>
      <p>{item.summary}</p>
      <div className="badges">
        <Badge tone={sourceType === 'github' ? 'sky' : 'violet'}>{sourceType}</Badge>
        {p.capability_type && <Badge tone="green">{p.capability_type}</Badge>}
        <Badge tone={reproTag as 'green' | 'sky' | 'slate' | 'amber'}>{reproText}</Badge>
        {p.is_web && <Badge tone="amber">Web{p.web_framework ? `:${p.web_framework}` : ''}</Badge>}
      </div>
    </div>
    <div className="score-ring">{item.score}</div>
  </div>;
}

// ========== 能力库（改动 1: 4 个视图 + 改动 3: classifyBatch 按钮）==========
function CapabilityLibrary({ items, openDetail }: { items: CapabilityItem[]; openDetail: (item: CapabilityItem) => void }) {
  const [viewMode, setViewMode] = useState<'列表视图' | '能力分类' | '应用场景' | '代码可用性'>('列表视图');

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

  // 【改动 1】代码可用性视图：按 has_real_code 分组
  const codeGroups = useMemo(() => ({
    '有代码': items.filter(i => i.payload?.implementation_depth?.has_real_code),
    '无代码': items.filter(i => !i.payload?.implementation_depth?.has_real_code),
  }), [items]);

  return <div className="grid">
    <div className="view-switch">
      {(['列表视图', '能力分类', '应用场景', '代码可用性'] as const).map(v => <span key={v} className={`view-pill ${viewMode === v ? 'active' : ''}`} onClick={() => setViewMode(v)}>{v}</span>)}
    </div>
    {items.length === 0 && <EmptyState title="能力库为空" description="先跑 capabilities.from_news_pipeline 生成能力卡" />}

    {/* 列表视图 */}
    {items.length > 0 && viewMode === '列表视图' && <div className="table-card"><table className="data-table"><thead><tr><th>能力</th><th>场景</th><th>技术点</th><th>评分</th><th>复现</th><th>转化</th></tr></thead><tbody>
      {items.map(item => { const p = item.payload ?? {}; return <tr key={item.id} className="clickable" onClick={() => openDetail(item)}>
        <td><div className="table-title">{item.title}</div><div className="table-sub">{p.source_type ?? ''} · {item.source_url?.split('/')[2] ?? ''}</div></td>
        <td>{(p.application_scenarios ?? []).join(' / ')}</td>
        <td>{(p.tech_points ?? []).slice(0, 2).map(t => <Badge key={t} tone="slate">{t}</Badge>)}</td>
        <td><div className="score-ring">{item.score}</div></td>
        <td><Badge tone={p.repro_status === 'candidate' ? 'green' : 'amber'}>{p.repro_status ?? '未知'}</Badge></td>
        <td><Badge tone="violet">{p.conversion_status ?? '待评估'}</Badge></td>
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

    {/* 代码可用性视图 */}
    {items.length > 0 && viewMode === '代码可用性' && <div className="grid cols-2">
      {Object.entries(codeGroups).map(([label, groupItems]) => (
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
  const [selectedIdx, setSelectedIdx] = useState(0);
  const selected = runs[selectedIdx];
  const capabilityItem = items.find(i => i.id === selected?.item_id);

  return <div className="grid">
    {runs.length === 0 && <EmptyState title="暂无复现任务" description="从今日能力或能力库点击「加入复现」触发" />}
    {runs.length > 0 && <div className="grid cols-2">
      <div className="panel">
        <div className="panel-head"><h3>复现任务 ({runs.length})</h3><span>自动复现状态</span></div>
        <div className="panel-body">
          {runs.map((r, i) => <div key={r.id} className={`asis-card clickable ${i === selectedIdx ? 'active' : ''}`} onClick={() => setSelectedIdx(i)}>
            <div className="rank">{i + 1}</div>
            <div><h4>{r.repo_url?.split('/').slice(-1)[0] ?? `task-${r.id}`}</h4>
              <div className="badges"><Badge tone={r.status === 'failed' ? 'red' : r.status === 'success' ? 'green' : r.status === 'running' ? 'sky' : 'slate'}>{r.status}</Badge>
              <Badge tone="slate">trigger: {r.trigger}</Badge>{r.web_port && <Badge tone="amber">port: {r.web_port}</Badge>}</div>
            </div><div />
          </div>)}
        </div>
      </div>
      <div className="panel">
        <div className="panel-head"><h3>复现详情</h3><span>实时日志 / 报告 / 产物</span></div>
        <div className="panel-body">
          {selected && <ReproDetailContent task={selected} capabilityItem={capabilityItem} openDetail={openDetail} />}
        </div>
      </div>
    </div>}
  </div>;
}

function ReproDetailContent({ task, capabilityItem, openDetail }: { task: ReproTask; capabilityItem?: CapabilityItem; openDetail: (item: CapabilityItem) => void }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [logs, setLogs] = useState<{ line: string; kind: string }[]>([]);
  const [streaming, setStreaming] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const cleanupRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    if (task.status === 'running' || task.status === 'queued') {
      setStreaming(true);
      setLogs([]);
      cleanupRef.current = streamReproLogs(task.id,
        (line, kind) => setLogs(prev => [...prev, { line, kind }]),
        (status) => { if (status === 'success' || status === 'failed' || status === 'timeout') { setStreaming(false); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } },
        () => setStreaming(false)
      );
      return () => { cleanupRef.current?.(); };
    }
  }, [task.id, task.status, qc]);

  useEffect(() => { if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight; }, [logs]);

  const report = task.report ?? capabilityItem?.payload?.repro_report;
  const p = capabilityItem?.payload ?? {};

  return <div className="grid">
    {streaming && <div className="log-stream" ref={logRef}>{logs.map((l, i) => <div key={i} className={`log-line log-${l.kind}`}>{l.line}</div>)}{logs.length === 0 && <div className="muted small">等待日志输出…</div>}</div>}
    {!streaming && (task.log_excerpt || task.result) && <div className="log-stream">{(task.log_excerpt || task.result || '').split('\n').map((line, i) => <div key={i} className={`log-line log-${classifyLogLine(line)}`}>{line}</div>)}</div>}
    {!streaming && !task.log_excerpt && !task.result && task.status === 'queued' && <div className="empty-hint">任务已排队，等待复现调度…</div>}
    {report && <div className="field-grid">
      <div className="cap-field"><span>报告状态</span><b style={{ color: report.status === 'success' ? 'var(--green)' : 'var(--rose)' }}>{report.status}</b></div>
      <div className="cap-field"><span>Level</span><b>{report.level ?? '-'}</b></div>
      <div className="cap-field"><span>项目类型</span><b>{report.project_type ?? '-'}</b></div>
      <div className="cap-field"><span>摘要</span><b style={{ fontSize: 11, fontWeight: 400 }}>{report.summary}</b></div>
    </div>}
    {report?.blockers && report.blockers.length > 0 && <div className="cap-field"><span>Blockers</span>{report.blockers.map((b, i) => <div key={i} style={{ color: 'var(--rose)', fontSize: 11 }}>• {b}</div>)}</div>}
    {report?.gotchas && report.gotchas.length > 0 && <div className="cap-field"><span>Gotchas</span>{report.gotchas.map((g, i) => <div key={i} style={{ color: 'var(--amber)', fontSize: 11 }}>• {g}</div>)}</div>}
    <div className="split">
      <button className="btn primary" onClick={async () => { if (capabilityItem) { try { await startRepro(capabilityItem.id, p.is_web ?? false); toast('已重跑复现', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } catch (e) { toast(`重跑失败: ${e}`, 'error'); } } }}>重跑</button>
      <button className="btn" onClick={async () => { try { await stopRepro(task.id); toast('已停止', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } catch (e) { toast(`停止失败: ${e}`, 'error'); } }}>停止</button>
      <button className="btn" onClick={async () => { try { await cleanupRepro(task.id); toast('已清理', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } catch (e) { toast(`清理失败: ${e}`, 'error'); } }}>清理</button>
      {capabilityItem && <button className="btn" onClick={() => openDetail(capabilityItem)}>查看能力详情</button>}
    </div>
  </div>;
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
    <div className="drawer-section"><h3>项目摘要</h3><p>{item?.summary ?? initialItem.summary}</p></div>
    {p.repro_summary && <div className="drawer-section"><h3>复现摘要</h3><p style={{ color: 'var(--green)' }}>{p.repro_summary}</p></div>}
    <div className="drawer-section"><h3>能力类型</h3><div className="badges">{p.capability_type && <Badge tone="green">{p.capability_type}</Badge>}{p.sub_type && <Badge tone="sky">{p.sub_type}</Badge>}</div></div>
    {p.application_scenarios && p.application_scenarios.length > 0 && <div className="drawer-section"><h3>应用场景</h3><div className="badges">{p.application_scenarios.map(s => <Badge key={s} tone="violet">{s}</Badge>)}</div></div>}
    {p.tech_points && p.tech_points.length > 0 && <div className="drawer-section"><h3>技术点</h3>{p.tech_points.map((t, i) => <p key={i}>• {t}</p>)}</div>}
    {p.score_breakdown && Object.keys(p.score_breakdown).length > 0 && <div className="drawer-section"><h3>评分依据</h3><div className="field-grid">{Object.entries(p.score_breakdown).map(([k, v]) => { const pct = Math.round(v * 100); const color = v >= 0.8 ? 'var(--green)' : v >= 0.5 ? 'var(--sky)' : 'var(--amber)'; return <div className="cap-field" key={k}><span>{k}</span><b style={{ color }}>{pct}%</b></div>; })}</div></div>}
    {p.implementation_depth && <div className="drawer-section"><h3>实现深度</h3><p>有真实代码: {p.implementation_depth.has_real_code ? '✓' : '✗'} | 有测试: {p.implementation_depth.has_tests ? '✓' : '✗'} | 有评估: {p.implementation_depth.has_eval ? '✓' : '✗'}</p></div>}
    <div className="drawer-section"><h3>复现 & 转化</h3><div className="badges"><Badge tone={p.repro_status === 'candidate' ? 'green' : 'amber'}>{p.repro_status ?? '未知'}</Badge><Badge tone="violet">{p.conversion_status ?? '待评估'}</Badge></div>{p.code_url && <p style={{ marginTop: 6 }}><a href={p.code_url} target="_blank" rel="noopener" style={{ color: 'var(--sky)' }}>{p.code_url}</a></p>}</div>
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
      <button className="pill-button primary" onClick={onRepro}>加入复现</button>
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
