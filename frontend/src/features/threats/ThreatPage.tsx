import { useMemo, useState, useEffect, useRef, type ComponentType } from 'react';
import { ThemeToggle } from '../../components/ThemeToggle';
import { Star, Github, LayoutGrid, Database, Activity, RefreshCw, BrainCircuit, Link2, type LucideIcon } from 'lucide-react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchTargets, fetchAssets, fetchSurfaceStats, postJson, getJson, type AiAssociationResult } from '../../api/client';
import { Card, Drawer, EmptyState, MetricCard } from '../../components/ui';
import type { ThreatAsset, ThreatRepo } from '../../types/threat';
import { assetFromItem } from './threatAdapters';
import { surfaces as staticSurfaces } from './threatStaticData';
import { RepoDrawerContent } from './RepoDrawer';
import { filterReasonLabel } from './filterLabels';
import { AssocView } from './assoc/AssocView';
import { useToast } from '../../components/Toast';
import { useDrawerStack } from '../../components/DrawerStack';
import { OpsOverview } from './ops/OpsOverview';
import { OpsTasks } from './ops/OpsTasks';
import { OpsSources } from './ops/OpsSources';
import { OpsAISummary } from './ops/OpsAISummary';

export type ViewId = 'today' | 'repos' | 'surface' | 'assets' | 'assoc' | 'ops-overview' | 'ops-tasks' | 'ops-sources' | 'ops-ai-summary';

const navGroups: Array<{ title: string; items: Array<{ id: ViewId; icon: LucideIcon; title: string }> }> = [
  { title: '开源威胁洞察', items: [
    { id: 'today', icon: Star, title: '今日关注' },
    { id: 'repos', icon: Github, title: '代码仓' },
    { id: 'surface', icon: LayoutGrid, title: '攻击面视图' },
    { id: 'assets', icon: Database, title: '资产库' },
    { id: 'assoc', icon: Link2, title: '资产↔仓关联' }
  ]},
  { title: '运营', items: [
    { id: 'ops-overview', icon: Activity, title: '运营概览' },
    { id: 'ops-tasks', icon: RefreshCw, title: '采集任务' },
    { id: 'ops-sources', icon: Database, title: '数据源' },
    { id: 'ops-ai-summary', icon: BrainCircuit, title: 'AI 分析汇总' }
  ]}
];

interface FilterState {
  search: string;
  grade: string;
  surface: string;
  onlyCve: boolean;
  onlyHigh: boolean;
  /** 是否显示已被规则过滤掉的疑似无效仓（默认关闭＝只显示过滤后的结果）。 */
  showFiltered: boolean;
}

export function ThreatPage() {
  const [view, setView] = useState<ViewId>('today');
  const [filters, setFilters] = useState<FilterState>({ search: '', grade: 'all', surface: 'all', onlyCve: false, onlyHigh: false, showFiltered: false });
  const [selectedAsset, setSelectedAsset] = useState<ThreatAsset | null>(null);
  const [currentPage, setCurrentPage] = useState(1);
  const { push } = useDrawerStack();
  const { toast } = useToast();
  const qc = useQueryClient();

  // Fetch targets with pagination + server-side filtering (summary fields only = ~1KB/item instead of 103KB)
  const { data: targetsData, isLoading, error } = useQuery({
    queryKey: ['threats-targets', currentPage, filters],
    queryFn: () => fetchTargets(currentPage, 20, filters.surface !== 'all' ? filters.surface : '', filters.grade !== 'all' ? filters.grade : '', filters.search, filters.showFiltered),
    staleTime: 300_000, // 5 minutes
  });

  // Convert summary items to ThreatRepo (lightweight — no full payload)
  const repos = useMemo(() => {
    return (targetsData?.items ?? []).map(item => {
      const i = item as Record<string, unknown>;
      const signals = i.signals_summary as Record<string, unknown> ?? {};
      const as = i.attack_surface_summary as Record<string, unknown> ?? {};
      return {
        id: String(i.id ?? ''),
        title: String(i.title ?? ''),
        org: String(i.raw_org ?? ''),
        name: String(i.raw_name ?? ''),
        url: String(i.source_url ?? ''),
        summary: String(i.summary ?? ''),
        score: Number(as.score ?? i.score ?? 0),
        grade: String(as.grade ?? ''),
        status: String(i.status ?? 'active'),
        surface: String(as.surface ?? ''),
        stars: Number(i.stars ?? 0),
        cve: Number(signals.cve_count ?? 0),
        sa: Number(signals.sa_count ?? 0),
        sec: Number(signals.broad_sec_count ?? 0),
        filtered: Boolean(i.filtered ?? false),
        filteredReason: String(i.filtered_reason ?? ''),
        breakdown: ((i.attack_surface as Record<string, unknown> ?? {})?.breakdown ?? i.breakdown) as Record<string, number> ?? {},
        reasons: (i.reasons as string[]) ?? [],
        evidence: [] as string[],
        assets: [] as string[],
        raw: {} as Record<string, unknown>,
        aiCalibrated: Boolean(i.aiCalibrated),
      } as ThreatRepo;
    });
  }, [targetsData]);

  const totalPages = targetsData?.pages ?? 1;
  const totalRepos = targetsData?.total ?? 0;
  const hiddenRepos = targetsData?.filtered_hidden ?? 0;

  const viewRef = useRef<HTMLDivElement>(null);

  // Reset scroll only when view (page) changes, not on every re-render
  useEffect(() => { if (viewRef.current) viewRef.current.scrollTop = 0; }, [view]);

  const openRepo = (repo: ThreatRepo) => {
    push({
      title: `${repo.org}/${repo.name}`,
      // 第二行是仓库链接,正文拉到详情后自己回写(RepoDrawer.update),这里只放占位 ——
      // 入口不止这一个,且有的入口(资产抽屉的 AI 关联)手里根本没有 URL。
      subtitle: '正在加载仓库链接…',
      render: (drawerId: string) => <RepoDrawerContent drawerId={drawerId} repoId={repo.id} onViewAssoc={() => setView('assoc')} onOpenAsset={setSelectedAsset} />,
    });
  };

  // Reset page when filters change
  useEffect(() => { setCurrentPage(1); }, [filters.grade, filters.surface, filters.search, filters.showFiltered]);

  const repoGrades = unique(['A', 'B', 'C', 'D']);
  const repoSurfaces = unique(staticSurfaces.map(s => s.id));

  return <main className="main">
    <aside className="ai4sec-sidebar">
      <a href="/" style={{ display: "block", padding: "8px 12px", color: "var(--accent)", fontSize: 12, textDecoration: "none", borderBottom: "1px solid var(--line)" }}>&larr; 返回</a>
      <div className="ai4sec-sidebar-head"><div className="label"><span className="dot" /><span>威胁洞察</span></div><h2>开源目标与运营</h2><p>开源威胁洞察围绕"发现目标、判断风险、查看证据、深挖关联"的挖洞动线组织。</p></div>
      <nav className="nav-scroll">{navGroups.map(group => <div className="nav-group" key={group.title}><div className="group-title">{group.title}</div>{group.items.map(item => { const Icon = item.icon; return <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} onClick={() => setView(item.id)}><Icon size={18} /><span>{item.title}</span></button>; })}</div>)}</nav>
      <div className="ai4sec-sidebar-note">目标详情不是单独页签；从今日关注、代码仓、资产↔仓关联点击对象后打开。资产关联以 AI 边为准（直连/推断/弱），逐条可追溯、可复核。</div>
    <div className="ai4sec-sidebar-footer" style={{ marginTop: "auto", padding: "8px 12px", borderTop: "1px solid var(--line)", display: "flex", alignItems: "center" }}><ThemeToggle /></div>
    </aside>
    <section className="content">
      <section className="content-head">
        <div className="content-title"><span className="label">{navGroups.flatMap(g => g.items).find(i => i.id === view)?.title ?? '威胁洞察'}</span><h1>{heroTitle(view)}</h1><p>{heroCopy(view)}</p></div>
        <div className="head-actions">{view === 'repos' ? <FiltersBar filters={filters} setFilters={setFilters} grades={repoGrades} surfaces={repoSurfaces} /> : <><label className="search"><span>⌕</span><input placeholder="搜索标题 / CVE / 仓库 / 资产" onChange={() => {}} /></label><button className="btn primary" onClick={async () => { await qc.invalidateQueries(); toast('数据已刷新', 'success'); }}>刷新数据</button></>}</div>
      </section>
      <div className="content-body view" ref={viewRef}>
        {isLoading && <EmptyState title="正在加载" description="从 /api/threats/targets 拉取数据。" />}
        {error && <EmptyState title="加载失败" description={(error as Error).message} />}
        {!isLoading && !error && renderView(view, repos, filters, setFilters, openRepo, setSelectedAsset, setView, currentPage, totalPages, totalRepos, hiddenRepos, setCurrentPage)}
        <AssetDrawer asset={selectedAsset} onClose={() => setSelectedAsset(null)} openRepo={openRepo} />
      </div>
    </section>
  </main>;
}

function renderView(view: ViewId, repos: ThreatRepo[], filters: FilterState, setFilters: (filters: FilterState) => void, openRepo: (repo: ThreatRepo) => void, openAsset: (asset: ThreatAsset) => void, setView: (view: ViewId) => void, currentPage: number, totalPages: number, totalRepos: number, hiddenRepos: number, setCurrentPage: (page: number) => void) {
  if (view === 'today') return <ThreatToday repos={repos} openRepo={openRepo} setView={setView} setFilters={setFilters} />;
  if (view === 'repos') return <ThreatRepos repos={repos} filters={filters} setFilters={setFilters} openRepo={openRepo} currentPage={currentPage} totalPages={totalPages} totalRepos={totalRepos} hiddenRepos={hiddenRepos} setCurrentPage={setCurrentPage} />;
  if (view === 'surface') return <ThreatSurface repos={repos} openRepo={openRepo} setFilters={setFilters} setView={setView} />;
  if (view === 'assets') return <ThreatAssets openAsset={openAsset} />;
  if (view === 'assoc') return <AssocView openRepo={openRepo} openAsset={openAsset} />;
  if (view === 'ops-overview') return <OpsOverview setView={setView} />;
  if (view === 'ops-tasks') return <OpsTasks />;
  if (view === 'ops-sources') return <OpsSources />;
  if (view === 'ops-ai-summary') return <OpsAISummary openRepo={openRepo} openAsset={openAsset} />;
  return <EmptyState title="未知页面" />;
}

function ThreatToday({ repos, openRepo, setView, setFilters }: { repos: ThreatRepo[]; openRepo: (repo: ThreatRepo) => void; setView: (view: ViewId) => void; setFilters: (filters: FilterState) => void }) {
  const highRisk = repos.filter(r => r.score >= 75).length;
  const withCve = repos.filter(r => r.cve > 0).length;
  const focus = [
    { type: '高风险仓库', kind: 'repo' as const, repo: repos[0], why: 'A 级高风险目标，适合优先进入代码审计和漏洞假设验证。' },
    { type: '安全线索仓库', kind: 'repo' as const, repo: repos.find((repo) => repo.cve > 20 || repo.sec > 20) ?? repos[1], why: '命中过 CVE / SA / security issue，适合做公告与依赖复核。' },
  ].filter((item) => item.kind === 'repo' ? Boolean(item.repo) : false);
  const kpiJump = (type: 'gradeA' | 'securitySignals' | 'assetChanges' | 'weakRelations') => {
    if (type === 'gradeA') { setFilters({ search: '', grade: 'A', surface: 'all', onlyCve: false, onlyHigh: false, showFiltered: false }); setView('repos'); return; }
    if (type === 'securitySignals') { setFilters({ search: '', grade: 'all', surface: 'all', onlyCve: false, onlyHigh: false, showFiltered: false }); setView('repos'); return; }
    if (type === 'assetChanges') { setView('assets'); return; }
    if (type === 'weakRelations') { setView('assoc'); return; }
  };
  return <div className="grid">
    <div className="grid cols-4">
      <MetricCard label="A级仓库" value={highRisk} hint="风险评分为 A 的代码仓；点击进入代码仓并筛选 A 级。" tone="red" onClick={() => kpiJump('gradeA')} />
      <MetricCard label="安全线索项目" value={withCve} hint="命中过 CVE / SA / security issue 的代码仓；点击查看有安全线索的代码仓。" tone="amber" onClick={() => kpiJump('securitySignals')} />
      <MetricCard label="资产变化" value="—" hint="点击查看相关资产。" tone="green" onClick={() => kpiJump('assetChanges')} />
      <MetricCard label="待复核关联" value="—" hint="点击进入资产↔仓关联，筛弱关联复核。" tone="violet" onClick={() => kpiJump('weakRelations')} />
    </div>
    <div className="grid cols-2">
      {focus.map((item) => <div className="focus-card" key={`${item.type}-${item.repo.id}`} onClick={() => openRepo(item.repo)}>
        <div className="row-title"><span className={`badge ${item.repo.grade || 'C'}`}>{item.type}</span><span className="muted small">点击钻取</span></div>
        <h3>{item.repo.org}/{item.repo.name}</h3>
        <p>{item.why}</p>
        <div className="split"><span className={`badge ${item.repo.grade || 'C'}`}>Grade {item.repo.grade}</span><span className="badge">{item.repo.surface}</span><span className="badge">score {Math.round(item.repo.score)}</span></div>
        <div className="split"><button className="btn primary" onClick={(event) => { event.stopPropagation(); openRepo(item.repo); }}>查看详情</button></div>
      </div>)}
    </div>
  </div>;
}

function ThreatRepos({ repos, filters, setFilters, openRepo, currentPage, totalPages, totalRepos, hiddenRepos, setCurrentPage }: { repos: ThreatRepo[]; filters: FilterState; setFilters: (filters: FilterState) => void; openRepo: (repo: ThreatRepo) => void; currentPage: number; totalPages: number; totalRepos: number; hiddenRepos: number; setCurrentPage: (page: number) => void; }) {
  const pageNav = totalPages > 1 ? <div className="split" style={{ justifyContent: 'center', gap: 6 }}>
    <button className="btn sm" disabled={currentPage <= 1} onClick={() => setCurrentPage(currentPage - 1)}>上一页</button>
    {Array.from({ length: Math.min(totalPages, 10) }, (_, i) => {
      const p = i + 1;
      const showP = totalPages <= 10 ? p : (currentPage <= 5 ? p : (currentPage + (p - 6) > totalPages ? totalPages - 9 + i : currentPage - 5 + i));
      if (showP < 1 || showP > totalPages) return null;
      return <button key={showP} className={`btn sm ${showP === currentPage ? 'primary' : ''}`} onClick={() => setCurrentPage(showP)}>{showP}</button>;
    })}
    {totalPages > 10 && currentPage < totalPages - 5 && <span className="muted small">...{totalPages}</span>}
    <button className="btn sm" disabled={currentPage >= totalPages} onClick={() => setCurrentPage(currentPage + 1)}>下一页</button>
  </div> : null;
  return <div className="grid">
    <div className="row-title" style={{ marginBottom: 8 }}>
      <span className="muted small">共 {totalRepos} 个代码仓 · 第 {currentPage}/{totalPages} 页{filters.showFiltered ? ' · 含已过滤' : ''}</span>
      <span className="muted small">
        {!filters.showFiltered && hiddenRepos > 0 ? ` · 已按规则隐藏 ${hiddenRepos} 个疑似无效仓（空壳/样例/镜像/文档）` : ''}
        {filters.grade !== 'all' ? ` · ${filters.grade} 级` : ''}{filters.surface !== 'all' ? ` · ${filters.surface}` : ''}{filters.search ? ` · 搜索"${filters.search}"` : ''}
      </span>
    </div>
    {pageNav}
    <div className="table-card"><RepoTable repos={repos} openRepo={openRepo} /></div>
    {pageNav}
  </div>;
}

function ThreatSurface({ repos, openRepo, setFilters, setView }: { repos: ThreatRepo[]; openRepo: (repo: ThreatRepo) => void; setFilters: (filters: FilterState) => void; setView: (view: ViewId) => void }) {
  const { data: stats } = useQuery({ queryKey: ['threats-surface-stats'], queryFn: fetchSurfaceStats, staleTime: 300_000 });
  const surfaces = staticSurfaces;
  const [activeSurfaceId, setActiveSurfaceId] = useState(surfaces[0]?.id ?? 'kernel');
  const selected = surfaces.find(s => s.id === activeSurfaceId) ?? surfaces[0];
  const relatedRepos = repos.filter(r => r.surface === activeSurfaceId).sort((a, b) => b.score - a.score);
  // Real KPIs from aggregate stats endpoint (not limited to current page of 50)
  const totalRepos = stats?.total_repos ?? repos.length;
  const totalCves = stats?.total_cves ?? repos.reduce((sum, r) => sum + r.cve, 0);
  const totalSec = stats?.total_sec ?? repos.reduce((sum, r) => sum + r.sec, 0);
  // Per-surface counts from real aggregate stats
  const surfaceCounts = surfaces.map(s => {
    const st = stats?.per_surface?.[s.id];
    return {
      ...s,
      realCount: st?.count ?? repos.filter(r => r.surface === s.id).length,
      realCves: st?.cves ?? repos.filter(r => r.surface === s.id).reduce((sum, r) => sum + r.cve, 0),
      realSec: st?.sec ?? repos.filter(r => r.surface === s.id).reduce((sum, r) => sum + r.sec, 0),
    };
  });
  return <div className="grid">
    <div className="grid cols-3">
      <MetricCard label="相关代码仓" value={totalRepos} hint="从数据库实时统计的代码仓总数。" tone="sky" />
      <MetricCard label="CVE 总量" value={totalCves} hint="各代码仓 CVE 合计。" tone="amber" />
      <MetricCard label="安全线索" value={totalSec} hint="CVE / SA / security issue 合计。" tone="green" />
    </div>
    <div className="grid cols-2">
      <Card><h3>攻击面总览</h3><p className="muted small">点击左侧攻击面只切换本页分析；需要看仓库明细时，再点"查看该攻击面的代码仓"。</p><div className="surface-matrix">{surfaceCounts.map(s => <button key={s.id} className={`surface-matrix-item clickable ${s.id === activeSurfaceId ? 'active' : ''}`} onClick={() => setActiveSurfaceId(s.id)}><div className="row-title"><span><b>{s.icon} {s.title}</b></span><span className={`badge ${s.id === activeSurfaceId ? 'A' : 'C'}`}>{s.id === activeSurfaceId ? '当前' : '查看'}</span></div><p className="muted small">{s.desc}</p><div className="split"><span className="badge">代码仓 {s.realCount}</span><span className="badge">CVE {s.realCves}</span><span className="badge">线索 {s.realSec}</span></div><div className="score-bar" style={{ marginTop: 9 }}><i style={{ width: `${Math.min(100, Math.round(s.realCount / Math.max(1, totalRepos) * 100))}%` }} /></div></button>)}</div></Card>
      <div className="grid">
        <Card className="detail-card"><h3>{selected?.title} 聚合指标</h3><p>{selected?.purpose}</p><div className="asset-meta"><div><b>{relatedRepos.length}</b><span>相关代码仓</span></div><div><b>{relatedRepos.filter(r => r.grade === 'A').length}</b><span>A级仓库</span></div><div><b>{relatedRepos.reduce((sum, r) => sum + r.cve, 0)}</b><span>CVE</span></div><div><b>{relatedRepos.reduce((sum, r) => sum + r.sec, 0)}</b><span>安全线索</span></div><div><b>{relatedRepos.length ? Math.round(Math.max(...relatedRepos.map(r => r.score))) : 0}</b><span>最高风险分</span></div></div></Card>
        <Card><h3>该攻击面的代码仓样例</h3>{relatedRepos.length ? <div className="timeline">{relatedRepos.slice(0, 5).map(r => <div key={r.id} className="timeline-item clickable" onClick={() => openRepo(r)}><div className="row-title"><b>{r.org}/{r.name}</b><span className={`badge ${r.grade || 'C'}`}>Grade {r.grade || '?'}</span></div><span className="muted small">score {Math.round(r.score)} · CVE {r.cve} · Sec {r.sec} · {r.surface}</span></div>)}</div> : <p className="muted">当前 demo 没有内嵌该攻击面的代码仓详情；正式版从全量数据聚合。</p>}<div className="split" style={{ marginTop: 10 }}><button className="btn primary" onClick={() => { setFilters({ search: '', grade: 'all', surface: activeSurfaceId, onlyCve: false, onlyHigh: false, showFiltered: false }); setView('repos'); }}>查看代码仓筛选</button></div></Card>
        <div className="grid cols-2"><Card className="detail-card"><h3>挖洞路径</h3><div className="timeline">{(selected?.paths ?? []).map((p, i) => <div key={i} className="timeline-item">{p}</div>)}</div></Card><Card className="detail-card"><h3>代表证据</h3><div className="timeline">{(selected?.evidence ?? []).map((e, i) => <div key={i} className="timeline-item">{e}</div>)}</div></Card></div>
        <Card><h3>下一步研判假设</h3><div className="timeline">{(selected?.hypotheses ?? []).map((h, i) => <div key={i} className="timeline-item">{h}</div>)}</div></Card>
      </div>
    </div>
  </div>;
}

function ThreatAssets({ openAsset }: { openAsset: (asset: ThreatAsset) => void }) {
  const { data: assetData, isLoading } = useQuery({ queryKey: ['threats-assets'], queryFn: fetchAssets });
  const assets = useMemo(() => {
    const all = (assetData?.items || []).map(assetFromItem);
    // Merge ascendhub: combine detail items (with name/publisher) and tags items (with versionTags) by hubId
    const ascendhubMap = new Map<string, ThreatAsset>();
    const result: ThreatAsset[] = [];
    // 固件：一条 = 一个唯一下载包（后端按 downloadUrl 已合并）；这里只做兜底去重，并把型号并起来
    const firmwareMap = new Map<string, ThreatAsset>();
    all.forEach(a => {
      if (a.source === 'ascendhub' && a.hubId) {
        if (ascendhubMap.has(a.hubId)) {
          const existing = ascendhubMap.get(a.hubId)!;
          // Merge versionTags from tags response into detail item
          if (a.versionTags?.length && !existing.versionTags?.length) {
            existing.versionTags = a.versionTags;
          }
          // Merge detail fields from detail response into tags-only item
          if (a.publisher && !existing.publisher) existing.publisher = a.publisher;
          if (a.size && !existing.size) existing.size = a.size;
          if (a.labelNames?.length && !existing.labelNames?.length) existing.labelNames = a.labelNames;
          if (a.fullDescription && !existing.fullDescription) existing.fullDescription = a.fullDescription;
          if (a.downloadCount != null && existing.downloadCount == null) existing.downloadCount = a.downloadCount;
        } else {
          ascendhubMap.set(a.hubId, a);
          result.push(a);
        }
      } else if (a.source === 'firmware') {
        const key = a.packageName || a.title;
        const existing = firmwareMap.get(key);
        if (existing) {
          const merged = new Set([...(existing.models ?? []), ...(a.models ?? [])]);
          if (merged.size) existing.models = Array.from(merged);
          if (a.cannVersion && !existing.cannVersion) existing.cannVersion = a.cannVersion;
        } else {
          firmwareMap.set(key, a);
          result.push(a);
        }
      } else {
        result.push(a);
      }
    });
    return result;
  }, [assetData]);
  const [assetType, setAssetType] = useState('all');
  const [confidence, setConfidence] = useState('all');
  const [firmwareKind, setFirmwareKind] = useState('all');
  const firmwareKinds = useMemo(
    () => Array.from(new Set(assets.filter(a => a.type === 'firmware').map(a => a.category || 'unknown'))),
    [assets],
  );
  const filtered = assets.filter(a =>
    (assetType === 'all' || a.type === assetType)
    && (confidence === 'all' || a.confidence === confidence)
    && (firmwareKind === 'all' || a.type !== 'firmware' || (a.category || 'unknown') === firmwareKind),
  );
  if (isLoading) return <EmptyState title="资产加载中..." />;
  return <div className="grid">
    <div className="split">
      <select className="select" value={assetType} onChange={e => setAssetType(e.target.value)}><option value="all">全部资产</option><option value="firmware">固件</option><option value="image">镜像</option><option value="mirror">软件源</option><option value="openx_firmware">OpenX固件</option></select>
      <select className="select" value={confidence} onChange={e => setConfidence(e.target.value)}><option value="all">全部置信度</option><option value="direct">direct</option><option value="inferred">inferred</option><option value="weak">weak</option><option value="unknown">unknown</option></select>
      {firmwareKinds.length > 1 && <select className="select" value={firmwareKind} onChange={e => setFirmwareKind(e.target.value)}><option value="all">全部组件类型</option>{firmwareKinds.map(k => <option key={k} value={k}>{FIRMWARE_KIND_LABELS[k] || k}</option>)}</select>}
      <span className="muted small">共 {filtered.length} 个资产{assetType !== 'all' ? ` · ${assetType}` : ''}{confidence !== 'all' ? ` · ${confidence}` : ''}{firmwareKind !== 'all' ? ` · ${FIRMWARE_KIND_LABELS[firmwareKind] || firmwareKind}` : ''}</span>
    </div>
    <div className="grid cols-2">
      {(() => {
        const openxAssets = filtered.filter(a => a.type === 'openx_firmware');
        const firmwareAssets = filtered.filter(a => a.type === 'firmware');
        const otherAssets = filtered.filter(a => a.type !== 'openx_firmware' && a.type !== 'firmware');
        const groups = new Map<string, ThreatAsset[]>();
        openxAssets.forEach(a => { const key = a.deviceModel || a.category || '未知设备'; if (!groups.has(key)) groups.set(key, []); groups.get(key)!.push(a); });
        // 固件按组件类型(NPU/CPLD/BMC/BIOS/驱动…)分组，一组一张卡，展开看包
        const firmwareGroups = new Map<string, ThreatAsset[]>();
        firmwareAssets.forEach(a => { const key = a.category || 'unknown'; if (!firmwareGroups.has(key)) firmwareGroups.set(key, []); firmwareGroups.get(key)!.push(a); });
        return <>
          {Array.from(groups.entries()).map(([model, files]) => <OpenxGroupCard key={model} deviceModel={model} files={files} onClick={openAsset} />)}
          {Array.from(firmwareGroups.entries()).map(([kind, files]) => <FirmwareGroupCard key={kind} kind={kind} files={files} onClick={openAsset} />)}
          {otherAssets.map(asset => <AssetCard key={asset.id} asset={asset} onClick={() => openAsset(asset)} />)}
        </>;
      })()}
    </div>
  </div>;
}

function OpenxGroupCard({ deviceModel, files, onClick }: { deviceModel: string; files: ThreatAsset[]; onClick: (a: ThreatAsset) => void }) {
  const [expanded, setExpanded] = useState(false);
  const latest = files.reduce((max, f) => (f.latest || '') > max ? (f.latest || '') : max, '');
  return <div className="card asset-card" onClick={() => setExpanded(!expanded)}>
    <div className="row-title"><span className="badge">OpenX固件</span><span className="badge">{files.length} 个固件</span></div>
    <h3>{deviceModel}</h3>
    <div className="asset-meta">
      <div><b>{files[0]?.category || '-'}</b><span>设备分类</span></div>
      <div><b>{files.length}</b><span>固件包数</span></div>
      <div><b>{latest || '-'}</b><span>最新修改</span></div>
    </div>
    {expanded ? (
      <div className="timeline" style={{ marginTop: 10 }}>
        {files.map((f, i) => {
          const name = [f.softwareVersion, f.version, f.model, f.title].find(v => v && v !== '-') || '-';
          const size = f.size || '';
          const date = f.latest || '';
          const fileInfo = [size, date].filter(Boolean).join(' | ') || '-';
          return (
            <div key={i} className="timeline-item clickable" onClick={(e) => { e.stopPropagation(); onClick(f); }}>
              <div className="row-title"><b>{name}</b><span className="badge">{f.fileType || '-'}</span></div>
              <span className="muted small">{fileInfo}</span>
              {f.link || f.url ? <span className="muted small" style={{ wordBreak: 'break-all', display: 'block' }}>{f.link || f.url}</span> : null}
            </div>
          );
        })}
      </div>
    ) : <p className="muted small" style={{ marginTop: 8 }}>点击展开 {files.length} 个固件文件</p>}
  </div>;
}

/** 固件按组件类型分组的显示名。NPU 是驱动/工具链大堆头，CPLD/BMC/BIOS 才是硬件攻击面。 */
const FIRMWARE_KIND_LABELS: Record<string, string> = {
  NPU: 'NPU 固件/驱动',
  MCU: 'MCU 固件',
  CPLD: 'CPLD 固件',
  BMC: 'BMC 固件',
  iBMC: 'iBMC 固件',
  BIOS: 'BIOS 固件',
  iDriver: '驱动',
  CDR: 'CDR 固件',
  commercial: '商业固件（需登录下载）',
  unknown: '未分类固件',
};

/** 固件组卡：一张卡 = 一个组件类型，卡内是去重后的唯一下载包。 */
function FirmwareGroupCard({ kind, files, onClick }: { kind: string; files: ThreatAsset[]; onClick: (a: ThreatAsset) => void }) {
  const [expanded, setExpanded] = useState(false);
  const label = FIRMWARE_KIND_LABELS[kind] || kind;
  const latest = files.reduce((max, f) => (f.latest || '') > max ? (f.latest || '') : max, '');
  const models = new Set<string>();
  files.forEach(f => (f.models?.length ? f.models : [f.model || '']).forEach(m => { if (m && m !== '-') models.add(m); }));
  return <div className="card asset-card">
    <div className="row-title" style={{ cursor: 'pointer' }} onClick={() => setExpanded(!expanded)}><span className="badge">{label}</span><span className="badge">{files.length} 个固件包</span><span className="badge">{expanded ? '▼' : '▶'}</span></div>
    <h3>{label}</h3>
    <div className="asset-meta">
      <div><b>{files.length}</b><span>固件包数</span></div>
      <div><b>{models.size}</b><span>涉及型号</span></div>
      <div><b>{latest || '-'}</b><span>最新发布</span></div>
    </div>
    {expanded ? (
      <div className="timeline" style={{ marginTop: 10 }}>
        {files.map((f, i) => {
          const modelText = (f.models?.length ? f.models : [f.model]).filter(m => m && m !== '-').join(' / ') || '-';
          const info = [modelText, f.version && f.version !== '-' ? f.version : '', f.size || '', f.latest || ''].filter(Boolean).join(' | ');
          return (
            <div key={i} className="timeline-item clickable" onClick={() => onClick(f)}>
              <div className="row-title"><b style={{ wordBreak: 'break-all' }}>{f.packageName || f.title}</b><span className="badge">{f.fileType || '-'}</span></div>
              <span className="muted small">{info || '-'}</span>
              {f.link || f.url ? <span className="muted small" style={{ wordBreak: 'break-all', display: 'block' }}>{f.link || f.url}</span> : null}
            </div>
          );
        })}
      </div>
    ) : <p className="muted small" style={{ marginTop: 8 }}>点击展开 {files.length} 个固件包</p>}
  </div>;
}

function ImageVersionTags({ tags }: { tags: NonNullable<ThreatAsset['versionTags']> }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div style={{ marginTop: 8 }}>
      <div className="row-title" style={{ cursor: 'pointer' }} onClick={() => setExpanded(!expanded)}>
        <b className="muted small">版本标签 ({tags.length})</b>
        <span className="badge">{expanded ? '▼' : '▶'}</span>
      </div>
      {expanded ? (
        <div className="timeline" style={{ marginTop: 4 }}>
          {tags.map((t, i) => (
            <div key={i} className="timeline-item">
              <div className="row-title"><b>{t.tag}</b><span className="badge">{t.size || '-'}</span></div>
              <span className="muted small">{t.update_time || '-'} | 架构: {t.architectures?.join(', ') || '-'}</span>
            </div>
          ))}
        </div>
      ) : <p className="muted small" style={{ marginTop: 4 }}>点击展开 {tags.length} 个版本</p>}
    </div>
  );
}

function RepoTable({ repos, openRepo }: { repos: ThreatRepo[]; openRepo: (repo: ThreatRepo) => void }) {
  return <table><thead><tr><th>目标</th><th>风险</th><th>攻击面</th><th>安全线索</th><th>评分拆解</th><th>操作</th></tr></thead><tbody>{repos.map(repo => <tr className="clickable" key={repo.id} onClick={() => openRepo(repo)}>
    <td style={{ maxWidth: 320 }}><div className="repo-name">{repo.org}/{repo.name}</div><div className="repo-url">{repo.url}</div><div className="muted small" style={{ maxHeight: '2.6em', overflow: 'hidden' }}>{repo.summary}</div>{repo.filtered && <div className="filtered-note">已被规则过滤：{filterReasonLabel(repo.filteredReason)}</div>}</td>
    <td><span className={`badge ${repo.grade || 'C'}`}>Grade {repo.grade || '?'}</span>{repo.aiCalibrated && <span className="badge badge-sky" style={{ marginLeft: 4 }}>AI</span>}<div style={{ height: 7 }} /><div className="score-bar"><i style={{ width: `${Math.min(100, repo.score)}%` }} /></div><div className="small muted">{Math.round(repo.score)}</div></td>
    <td><span className="badge">{repo.surface}</span></td>
    <td>CVE {repo.cve}<br />SA {repo.sa}<br />Sec items {repo.sec}<div style={{ height: 7 }} />{(repo.cve + repo.sa + repo.sec) > 0 ? <button className="btn" onClick={(event) => { event.stopPropagation(); openRepo(repo); }}>{repo.cve + repo.sa + repo.sec} 条详情</button> : <span className="muted small">暂无详情</span>}</td>
    <td style={{ minWidth: 150 }}><ScoreBreakdown breakdown={repo.breakdown} mini /></td>
    <td><button className="btn primary" onClick={(event) => { event.stopPropagation(); openRepo(repo); }}>详情</button></td>
  </tr>)}</tbody></table>;
}

function formatNum(n: number): string {
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

function AssetCard({ asset, onClick }: { asset: ThreatAsset; onClick: () => void }) {
  const typeLabel = asset.type === 'firmware' ? '固件' : asset.type === 'image' ? '镜像' : asset.type === 'mirror' ? '软件源' : asset.type === 'openx_firmware' ? 'OpenX固件' : asset.type || '未知';
  return <div className="card asset-card" onClick={onClick}>
    <div className="row-title"><span className="badge">{typeLabel}</span>{asset.official && <span className="badge A">官方</span>}</div>
    <h3>{asset.title}</h3>
    <p>{asset.evidence || asset.summary}</p>
    {asset.type === 'mirror' ? (
      <div className="asset-meta">
        <div><b>{asset.catalog?.join(', ') || '-'}</b><span>分类</span></div>
        <div><b>{asset.syncState || '-'}</b><span>同步状态</span></div>
        <div><b>{asset.count || '-'}</b><span>包数量</span></div>
        <div><b>{asset.downloadCount ? formatNum(asset.downloadCount) : '-'}</b><span>下载量</span></div>
      </div>
    ) : asset.type === 'image' ? (
      <>
      <div className="asset-meta">
        <div><b>{asset.publisher || '-'}</b><span>发布者</span></div>
        <div><b>{asset.version || '-'}</b><span>版本</span></div>
        <div><b>{asset.size || '-'}</b><span>大小</span></div>
        <div><b>{asset.downloadCount ?? '-'}</b><span>下载次数</span></div>
      </div>
      {asset.labelNames?.length ? <div className="split" style={{ marginTop: 6 }}>{asset.labelNames.map((l, i) => <span key={i} className="badge">{l}</span>)}</div> : null}
      {asset.versionTags?.length ? <ImageVersionTags tags={asset.versionTags} /> : null}
      </>
    ) : asset.type === 'firmware' ? (
      <div className="asset-meta">
        <div><b>{asset.model || '-'}</b><span>型号</span></div>
        <div><b>{asset.meta || '-'}</b><span>产品类型</span></div>
        {asset.cannVersion && <div><b>{asset.cannVersion}</b><span>CANN版本</span></div>}
        <div><b>{asset.latest || '-'}</b><span>更新</span></div>
      </div>
    ) : asset.type === 'openx_firmware' ? (
      <div className="asset-meta">
        <div><b>{asset.deviceModel || asset.model || '-'}</b><span>设备型号</span></div>
        <div><b>{asset.softwareVersion || asset.version || '-'}</b><span>软件版本</span></div>
        <div><b>{asset.fileType || '-'}</b><span>文件类型</span></div>
        <div><b>{asset.size || '-'}</b><span>大小</span></div>
        <div><b>{asset.category || '-'}</b><span>分类</span></div>
        <div><b>{asset.latest || '-'}</b><span>修改时间</span></div>
      </div>
    ) : (
      <div className="asset-meta"><div><b>{asset.model || '-'}</b><span>型号/名称</span></div><div><b>{asset.version || '-'}</b><span>版本</span></div><div><b>{asset.count || '-'}</b><span>数量</span></div><div><b>{asset.latest || '-'}</b><span>更新</span></div></div>
    )}
    <div className="split"><button className="btn primary" onClick={(e) => { e.stopPropagation(); onClick(); }}>资产详情</button></div>
  </div>;
}

function AssetDrawer({ asset, onClose, openRepo }: { asset: ThreatAsset | null; onClose: () => void; openRepo: (repo: ThreatRepo) => void }) {
  const typeLabel = asset?.type === 'firmware' ? '固件' : asset?.type === 'image' ? '镜像' : asset?.type === 'mirror' ? '软件源' : asset?.type === 'openx_firmware' ? 'OpenX固件' : asset?.type || '未知';
  const [assocResult, setAssocResult] = useState<AiAssociationResult | null>(null);
  const [assocLoading, setAssocLoading] = useState(false);
  const [assocError, setAssocError] = useState<string | null>(null);

  useEffect(() => {
    setAssocResult(null);
    if (asset?.id) {
      getJson<AiAssociationResult>(`/api/threats/assets/${asset.id}/ai-associate`).then(setAssocResult).catch(() => {});
    }
  }, [asset?.id]);

  const handleAssociate = async () => {
    if (!asset?.id) return;
    setAssocLoading(true);
    setAssocError(null);
    try {
      const result = await postJson<AiAssociationResult>(`/api/threats/assets/${asset.id}/ai-associate`);
      setAssocResult(result);
    } catch (e) {
      setAssocError(String(e));
    } finally {
      setAssocLoading(false);
    }
  };

  return <Drawer open={Boolean(asset)} title={asset?.title ?? ''} subtitle={asset ? `${typeLabel} · ${asset.source}` : ''} onClose={onClose}>{asset && <>
    <div className="detail-card card"><h3>资产概览</h3><p>{asset.evidence || asset.summary || '暂无摘要。'}</p></div>
    <div className="detail-card card"><h3>详细信息</h3>
      {asset.type === 'mirror' ? (
        <div className="asset-meta">
          <div><b>{asset.catalog?.join(', ') || '-'}</b><span>分类</span></div>
          <div><b>{asset.syncState || '-'}</b><span>同步状态</span></div>
          <div><b>{asset.count || '-'}</b><span>包数量</span></div>
          <div><b>{asset.downloadCount ? formatNum(asset.downloadCount) : '-'}</b><span>下载量</span></div>
          <div><b>{asset.latest || '-'}</b><span>最后同步</span></div>
          <div><b>{asset.upstreamUrl || '-'}</b><span>上游源</span></div>
          <div><b>{asset.mirrorPath || '-'}</b><span>镜像路径</span></div>
        </div>
      ) : asset.type === 'image' ? (
        <div className="asset-meta">
          <div><b>{asset.publisher || '-'}</b><span>发布者</span></div>
          <div><b>{asset.version || '-'}</b><span>版本</span></div>
          <div><b>{asset.size || '-'}</b><span>大小</span></div>
          <div><b>{asset.downloadCount ?? '-'}</b><span>下载次数</span></div>
          <div><b>{asset.latest || '-'}</b><span>更新时间</span></div>
          <div><b>{asset.labelNames?.join(', ') || '-'}</b><span>标签</span></div>
        </div>
      ) : asset.type === 'firmware' ? (
        <div className="asset-meta">
          <div><b>{asset.model || '-'}</b><span>型号</span></div>
          <div><b>{asset.meta || '-'}</b><span>产品类型</span></div>
          {asset.cannVersion && <div><b>{asset.cannVersion}</b><span>CANN版本</span></div>}
          <div><b>{asset.latest || '-'}</b><span>更新</span></div>
        </div>
      ) : asset.type === 'openx_firmware' ? (
        <div className="asset-meta">
          <div><b>{asset.deviceModel || asset.model || '-'}</b><span>设备型号</span></div>
          <div><b>{asset.softwareVersion || asset.version || '-'}</b><span>软件版本</span></div>
          <div><b>{asset.fileType || '-'}</b><span>文件类型</span></div>
          <div><b>{asset.category || '-'}</b><span>设备分类</span></div>
          <div><b>{asset.link || asset.url || '-'}</b><span>下载链接</span></div>
        </div>
      ) : <p className="muted">暂无详细信息。</p>}
    </div>
    <div className="detail-card card">
      <h3>AI 关联分析</h3>
      {assocResult ? (
        <div>
          <p>{assocResult.associations?.summary || '已完成关联分析。'}</p>
          {assocResult.associations?.associations?.length ? (
            <div className="timeline" style={{ marginTop: 10 }}>
              {assocResult.associations.associations.map((a, i) => (
                <div key={i} className="timeline-item clickable" onClick={() => {
                  const repo: ThreatRepo = { id: a.repo_id, title: a.repo_name, org: a.repo_name.split('/')[0] || '', name: a.repo_name.split('/')[1] || a.repo_name, url: '', summary: '', score: 0, grade: '', status: '', surface: '', stars: 0, cve: 0, sa: 0, sec: 0, filtered: false, breakdown: {}, reasons: [], evidence: [], assets: [], raw: {} };
                  openRepo(repo);
                }}>
                  <div className="row-title"><b>{a.repo_name}</b><span className={`badge ${a.confidence === 'direct' ? 'A' : a.confidence === 'inferred' ? 'B' : 'C'}`}>{a.confidence}</span></div>
                  <span className="muted small">{a.reason}</span>
                </div>
              ))}
            </div>
          ) : <p className="muted">未发现关联的代码仓库。</p>}
          <span className="badge" style={{ marginTop: 8 }}>{assocResult.status === 'cached' ? '已缓存' : '新分析'}</span>
        </div>
      ) : assocLoading ? (
        <p className="muted">AI 关联分析中，请稍候 3-10 秒...</p>
      ) : assocError ? (
        <p className="muted small">分析失败: {assocError}</p>
      ) : (
        <button className="btn primary" onClick={handleAssociate}>开始 AI 关联分析</button>
      )}
    </div>
  </>}</Drawer>;
}

function FiltersBar({ filters, setFilters, grades, surfaces }: { filters: FilterState; setFilters: (filters: FilterState) => void; grades: string[]; surfaces: string[] }) {
  return <div className="filters"><input className="search" value={filters.search} onChange={event => setFilters({ ...filters, search: event.target.value })} placeholder="搜索组织/仓库/描述" /><select className="select" value={filters.grade} onChange={event => setFilters({ ...filters, grade: event.target.value })}><option value="all">全部等级</option>{grades.map(grade => <option key={grade}>{grade}</option>)}</select><select className="select" value={filters.surface} onChange={event => setFilters({ ...filters, surface: event.target.value })}><option value="all">全部攻击面</option>{surfaces.map(surface => <option key={surface}>{surface}</option>)}</select><label className="filter-check" title="默认只显示过滤后的结果；勾选后把被规则过滤掉的空壳/样例/镜像/文档仓一并显示，并在行内标注过滤理由。"><input type="checkbox" checked={filters.showFiltered} onChange={event => setFilters({ ...filters, showFiltered: event.target.checked })} /><span>显示已过滤</span></label></div>;
}

/** 过滤规则代号 → 中文说明（与后端 repo_filter.py 的 REASON_LABELS 保持一致）。 */
function ScoreBreakdown({ breakdown, mini = false }: { breakdown: Record<string, number>; mini?: boolean }) {
  const entries = Object.entries(breakdown ?? {}).slice(0, mini ? 5 : undefined);
  if (!entries.length) return <EmptyState title="暂无评分拆解" />;
  return <div className={mini ? 'breakdown mini' : 'breakdown'}>{entries.map(([key, value]) => <div className="break-row" key={key}><span title={key}>{scoreLabel(key)}</span><span className="bar"><i style={{ width: `${Math.min(100, Number(value) * 4)}%` }} /></span><b>{Number(value).toFixed(0)}</b></div>)}</div>;
}

function scoreLabel(key: string): string {
  return ({ attack_surface: '攻击面', cve: '历史 CVE', security_advisory: '安全公告', broad_security: '安全线索', severity: '严重性', exploit: 'Exploit', exposure: '暴露面', inherited: '继承分', language_vuln倾向: '语言风险', untrusted_input: '不可信输入', historical_cve: '历史 CVE', complexity_stars: '复杂度', security_boundary: '安全边界' } as Record<string, string>)[key] || key;
}

function heroTitle(view: ViewId): string {
  return ({ today: '今天有哪些目标值得看', repos: '开源代码仓目标库', surface: '攻击面评分与分布', assets: '固件 / 镜像 / Hub 资产库', assoc: '资产↔代码仓 AI 关联', 'ops-overview': '运营概览', 'ops-tasks': '采集任务', 'ops-sources': '数据源与采集目标', 'ops-ai-summary': 'AI 分析汇总' } as Record<ViewId, string>)[view];
}

function heroCopy(view: ViewId): string {
  return ({ today: '优先呈现高风险目标、CVE/SA/security issue 和推荐挖洞方向。', repos: '搜索、过滤、排序所有华为开源仓，并查看证据链。', surface: '按语言、输入面、历史漏洞、复杂度和安全边界拆分评分。', assets: '查看 firmware、AscendHub、mirror、OpenX Huawei 等资产线索。', assoc: 'AI 把资产与代码仓关联成一条条可追溯的边，两种视图读同一份数据：风险焦点看影响，泳道审计对状态。', 'ops-overview': '系统状态、数据新鲜度、AI 分析进度和快捷操作。', 'ops-tasks': '触发 pipeline、追踪 step 进度和产物。', 'ops-sources': '每个数据源的站点、组织、记录数与最近采集时间，并支持人工添加新的数据源和代码仓。', 'ops-ai-summary': 'AI 研判和资产关联的汇总视图。' } as Record<ViewId, string>)[view];
}

function unique(values: string[]): string[] { return Array.from(new Set(values)).filter(Boolean).sort(); }
