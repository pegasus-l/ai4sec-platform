import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Boxes, GitBranch, GitFork, Network, Radar, ShieldCheck, Target, Workflow } from 'lucide-react';
import { fetchFrontendContract } from '../../api/frontendContract';
import { Badge, Card, Drawer, EmptyState, MetricCard } from '../../components/ui';
import type { ThreatAsset, ThreatRepo, ThreatViewModel } from '../../types/threat';
import { adaptThreatContract } from './threatAdapters';
import { opsTasks, opsSources } from './threatStaticData';
import { ThreatGraphView } from './graph/ThreatGraphView';
import { RepoDrawerContent } from './RepoDrawer';
import { useDrawerStack } from '../../components/DrawerStack';

type ViewId = 'today' | 'repos' | 'surface' | 'assets' | 'graph' | 'queue' | 'ops-tasks' | 'ops-sources' | 'ops-rules' | 'ops-quality' | 'ops-queue';

const navGroups: Array<{ title: string; items: Array<{ id: ViewId; icon: string; title: string }> }> = [
  { title: '开源威胁洞察', items: [
    { id: 'today', icon: '★', title: '今日关注' },
    { id: 'repos', icon: '◎', title: '代码仓' },
    { id: 'surface', icon: '◈', title: '攻击面视图' },
    { id: 'assets', icon: '▣', title: '资产库' },
    { id: 'graph', icon: '✣', title: '关联图谱' },
    { id: 'queue', icon: '▤', title: '跟踪队列' }
  ]},
  { title: '运营', items: [
    { id: 'ops-tasks', icon: '↻', title: '采集任务' },
    { id: 'ops-sources', icon: '◇', title: '数据源' },
    { id: 'ops-rules', icon: '≋', title: '规则配置' },
    { id: 'ops-quality', icon: '◈', title: '质量审计' },
    { id: 'ops-queue', icon: '▤', title: '人工队列' }
  ]}
];

interface FilterState {
  search: string;
  grade: string;
  surface: string;
  onlyCve: boolean;
  onlyHigh: boolean;
}

export function ThreatPage() {
  const [view, setView] = useState<ViewId>('today');
  const [filters, setFilters] = useState<FilterState>({ search: '', grade: 'all', surface: 'all', onlyCve: false, onlyHigh: false });
  const [selectedAsset, setSelectedAsset] = useState<ThreatAsset | null>(null);
  const { push } = useDrawerStack();
  const { data, isLoading, error } = useQuery({ queryKey: ['frontend-contract'], queryFn: fetchFrontendContract });
  const model = useMemo(() => data ? adaptThreatContract(data) : null, [data]);

  const openRepo = (repo: ThreatRepo) => {
    push({
      title: '仓库详情',
      subtitle: `${repo.org}/${repo.name}`,
      render: () => model ? <RepoDrawerContent repo={repo} model={model} onViewGraph={() => setView('graph')} onOpenAsset={setSelectedAsset} /> : null,
    });
  };

  const visibleRepos = useMemo(() => filterRepos(model?.repos ?? [], filters), [model, filters]);
  const activeTitle = navGroups.flatMap(group => group.items).find(item => item.id === view)?.title ?? '威胁洞察';
  const repoGrades = model ? unique(model.repos.map(repo => repo.grade).filter(Boolean)) : [];
  const repoSurfaces = model ? unique(model.repos.map(repo => repo.surface).filter(Boolean)) : [];

  return <main className="main">
    <aside className="sidebar">
      <div className="sidebar-head"><div className="label"><span className="dot" /><span>威胁洞察</span></div><h2>开源目标与运营</h2><p>开源威胁洞察围绕“发现目标、判断风险、查看证据、加入跟踪”的挖洞动线组织。</p></div>
      <div className="domain-switcher">
        <button className="domain-btn active" type="button"><span className="domain-icon">OS</span><span className="domain-main"><strong>威胁洞察</strong><span>华为开源仓库风险与挖洞目标</span></span><span className="domain-tag">OPS</span></button>
      </div>
      <div className="data-basis"><div className="mini-stat"><span>目标仓库</span><strong>{model?.summary.totalRepos ?? '—'}</strong></div><div className="mini-stat"><span>CVE / SA</span><strong>{model ? `${model.summary.uniqueCve}/${model.summary.totalSa}` : '—'}</strong></div><div className="mini-stat"><span>资产条目</span><strong>{model?.summary.assets ?? '—'}</strong></div></div>
      <nav className="nav-scroll">{navGroups.map(group => <div className="nav-group" key={group.title}><div className="group-title">{group.title}</div>{group.items.map(item => <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} onClick={() => setView(item.id)}><span className="nav-left"><span className="nav-ico">{item.icon}</span><span className="nav-text"><b>{item.title}</b><small>{navMeta(item.id)}</small></span></span><span className="nav-meta">{navCount(item.id, model)}</span></button>)}</div>)}</nav>
      <div className="sidebar-note">目标详情不是单独页签；从今日关注、代码仓、关联图谱或跟踪队列点击对象后打开。资产关系默认按置信度展示，不做无证据强关联。</div>
    </aside>
    <section className="content">
      <section className="content-head">
        <div className="content-title"><span className="label">{activeTitle}</span><h1>{heroTitle(view)}</h1><p>{heroCopy(view)}</p></div>
        <div className="head-actions">{view === 'repos' && model ? <FiltersBar filters={filters} setFilters={setFilters} grades={repoGrades} surfaces={repoSurfaces} /> : <><label className="search"><span>⌕</span><input placeholder="搜索标题 / CVE / 仓库 / 资产" onChange={() => {}} /></label><button className="btn primary" onClick={() => location.reload()}>刷新数据</button><a className="btn" href="/api/threats/reports" target="_blank">查看报告 API</a></>}</div>
      </section>
      <div className="content-body view">
        {isLoading && <EmptyState title="正在加载威胁洞察数据" description="从 /api/frontend/v9 拉取统一契约。" />}
        {error && <EmptyState title="加载失败" description={(error as Error).message} />}
        {model && renderView(view, model, visibleRepos, filters, setFilters, openRepo, setSelectedAsset, setView)}
      </div>
    </section>
    <AssetDrawer asset={selectedAsset} onClose={() => setSelectedAsset(null)} />
  </main>;
}

function renderView(view: ViewId, model: ThreatViewModel, repos: ThreatRepo[], filters: FilterState, setFilters: (filters: FilterState) => void, openRepo: (repo: ThreatRepo) => void, openAsset: (asset: ThreatAsset) => void, setView: (view: ViewId) => void) {
  if (view === 'today') return <ThreatToday model={model} openRepo={openRepo} setView={setView} setFilters={setFilters} />;
  if (view === 'repos') return <ThreatRepos model={model} repos={repos} filters={filters} setFilters={setFilters} openRepo={openRepo} />;
  if (view === 'surface') return <ThreatSurface model={model} openRepo={openRepo} setFilters={setFilters} setView={setView} />;
  if (view === 'assets') return <ThreatAssets model={model} openAsset={openAsset} />;
  if (view === 'graph') return <ThreatGraphView model={model} openRepo={openRepo} openAsset={openAsset} />;
  if (view === 'queue') return <ThreatQueue model={model} />;
  return <ThreatOps model={model} kind={view} />;
}

function ThreatToday({ model, openRepo, setView, setFilters }: { model: ThreatViewModel; openRepo: (repo: ThreatRepo) => void; setView: (view: ViewId) => void; setFilters: (filters: FilterState) => void }) {
  const { summary } = model;
  const focus = model.today.slice(0, 4);
  const kpiJump = (type: 'gradeA' | 'securitySignals' | 'assetChanges' | 'weakRelations') => {
    if (type === 'gradeA') { setFilters({ search: '', grade: 'A', surface: 'all', onlyCve: false, onlyHigh: false }); setView('repos'); return; }
    if (type === 'securitySignals') { setFilters({ search: '', grade: 'all', surface: 'all', onlyCve: false, onlyHigh: false }); setView('repos'); return; }
    if (type === 'assetChanges') { setView('assets'); return; }
    if (type === 'weakRelations') { setView('graph'); return; }
  };
  return <div className="grid">
    <div className="grid cols-4">
      <MetricCard label="A级仓库" value={summary.highRisk} hint="风险评分为 A 的代码仓；点击进入代码仓并筛选 A 级。" tone="red" onClick={() => kpiJump('gradeA')} />
      <MetricCard label="安全线索项目" value={summary.withCve} hint="命中过 CVE / SA / security issue 的代码仓；点击查看有安全线索的代码仓。" tone="amber" onClick={() => kpiJump('securitySignals')} />
      <MetricCard label="资产变化" value={summary.assets} hint="今日新增或版本变化的固件/镜像资产；点击查看相关资产。" tone="green" onClick={() => kpiJump('assetChanges')} />
      <MetricCard label="待复核关联" value={summary.highRisk} hint="inferred / weak 的仓库-资产关系；点击进入关联图谱查看弱关联。" tone="violet" onClick={() => kpiJump('weakRelations')} />
    </div>
    <div className="grid cols-2">
      {focus.map((repo) => <button className="focus-card" key={repo.id} onClick={() => openRepo(repo)}>
        <div className="row-title"><Badge tone={repo.score >= 75 ? 'red' : 'amber'}>{repo.status}</Badge><span className="muted small">点击钻取</span></div>
        <h3>{repo.org}/{repo.name}</h3>
        <p>{repo.summary || repo.reasons[0] || '高价值威胁目标，建议进入研判。'}</p>
        <div className="split"><span className="badge A">Grade {repo.grade}</span><span className="badge">{repo.surface}</span><span className="badge">score {Math.round(repo.score)}</span></div>
        <div className="split"><button className="btn primary" onClick={(event) => { event.stopPropagation(); openRepo(repo); }}>查看详情</button><button className="btn" onClick={(event) => event.stopPropagation()}>加入跟踪</button></div>
      </button>)}
      <Card><PanelTitle icon={<ShieldCheck />} title="CVE Scout 概览" hint="安全线索来源" /> <StatsGrid data={{ ...summary.sourceStats, ...summary.scanModes }} /></Card>
    </div>
  </div>;
}

function ThreatRepos({ model, repos, filters, setFilters, openRepo }: { model: ThreatViewModel; repos: ThreatRepo[]; filters: FilterState; setFilters: (filters: FilterState) => void; openRepo: (repo: ThreatRepo) => void }) {
  return <div className="grid">
    <div className="table-card"><RepoTable repos={repos} openRepo={openRepo} /></div>
  </div>;
}

function ThreatSurface({ model, openRepo, setFilters, setView }: { model: ThreatViewModel; openRepo: (repo: ThreatRepo) => void; setFilters: (filters: FilterState) => void; setView: (view: ViewId) => void }) {
  const surfaces = model.surfaces ?? [];
  const [activeSurfaceId, setActiveSurfaceId] = useState(surfaces[0]?.id ?? 'kernel');
  const selected = surfaces.find(s => s.id === activeSurfaceId) ?? surfaces[0];
  const relatedRepos = model.repos.filter(r => r.surface === activeSurfaceId).sort((a, b) => b.score - a.score);
  const totalRepos = surfaces.reduce((sum, s) => sum + s.count, 0);
  const totalCves = surfaces.reduce((sum, s) => sum + s.cves, 0);
  const totalSec = surfaces.reduce((sum, s) => sum + (s.secItems ?? 0), 0);
  return <div className="grid">
    <div className="grid cols-3">
      <MetricCard label="相关代码仓" value={totalRepos} hint="全量旧数据口径的攻击面聚合数量。" tone="sky" />
      <MetricCard label="CVE 总量" value={totalCves} hint="各攻击面历史 CVE 聚合计数。" tone="amber" />
      <MetricCard label="安全线索" value={totalSec} hint="CVE / SA / security issue 合计。" tone="green" />
    </div>
    <div className="grid cols-2">
      <Card><h3>攻击面总览</h3><p className="muted small">点击左侧攻击面只切换本页分析；需要看仓库明细时，再点"查看该攻击面的代码仓"。</p><div className="surface-matrix">{surfaces.map(s => <button key={s.id} className={`surface-matrix-item clickable ${s.id === activeSurfaceId ? 'active' : ''}`} onClick={() => setActiveSurfaceId(s.id)}><div className="row-title"><span><b>{s.icon} {s.title}</b></span><span className={`badge ${s.id === activeSurfaceId ? 'A' : 'C'}`}>{s.id === activeSurfaceId ? '当前' : '查看'}</span></div><p className="muted small">{s.desc}</p><div className="split"><span className="badge">代码仓 {s.count}</span><span className="badge">A级 {s.gradeA}</span><span className="badge">CVE {s.cves}</span><span className="badge">资产 {s.assets}</span></div><div className="score-bar" style={{ marginTop: 9 }}><i style={{ width: `${Math.min(100, Math.round(s.count / Math.max(1, totalRepos) * 300))}%` }} /></div></button>)}</div></Card>
      <div className="grid">
        <Card className="detail-card"><h3>{selected?.title} 聚合指标</h3><p>{selected?.purpose}</p><div className="asset-meta"><div><b>{selected?.count}</b><span>相关代码仓</span></div><div><b>{selected?.gradeA}</b><span>A级仓库</span></div><div><b>{selected?.cves}</b><span>CVE</span></div><div><b>{selected?.secItems ?? 0}</b><span>安全线索</span></div><div><b>{selected?.assets}</b><span>关联资产</span></div><div><b>{selected?.score}</b><span>最高风险分</span></div></div></Card>
        <Card><h3>该攻击面的代码仓样例</h3>{relatedRepos.length ? <div className="timeline">{relatedRepos.slice(0, 5).map(r => <div key={r.id} className="timeline-item clickable" onClick={() => openRepo(r)}><div className="row-title"><b>{r.org}/{r.name}</b><span className={`badge ${r.grade || 'C'}`}>Grade {r.grade || '?'}</span></div><span className="muted small">score {Math.round(r.score)} · CVE {r.cve} · Sec {r.sec} · {r.surface}</span></div>)}</div> : <p className="muted">当前 demo 没有内嵌该攻击面的代码仓详情；正式版从全量数据聚合。</p>}<div className="split" style={{ marginTop: 10 }}><button className="btn primary" onClick={() => { setFilters({ search: '', grade: 'all', surface: activeSurfaceId, onlyCve: false, onlyHigh: false }); setView('repos'); }}>查看代码仓筛选</button></div></Card>
        <div className="grid cols-2"><Card className="detail-card"><h3>挖洞路径</h3><div className="timeline">{(selected?.paths ?? []).map((p, i) => <div key={i} className="timeline-item">{p}</div>)}</div></Card><Card className="detail-card"><h3>代表证据</h3><div className="timeline">{(selected?.evidence ?? []).map((e, i) => <div key={i} className="timeline-item">{e}</div>)}</div></Card></div>
        <Card><h3>下一步研判假设</h3><div className="timeline">{(selected?.hypotheses ?? []).map((h, i) => <div key={i} className="timeline-item">{h}</div>)}</div></Card>
      </div>
    </div>
  </div>;
}

function ThreatAssets({ model, openAsset }: { model: ThreatViewModel; openAsset: (asset: ThreatAsset) => void }) {
  const [assetType, setAssetType] = useState('all');
  const [confidence, setConfidence] = useState('all');
  const filtered = model.assets.filter(a => (assetType === 'all' || a.type === assetType) && (confidence === 'all' || a.confidence === confidence));
  return <div className="grid">
    <div className="split">
      <select className="select" value={assetType} onChange={e => setAssetType(e.target.value)}><option value="all">全部资产</option><option value="firmware">固件</option><option value="image">镜像</option><option value="mirror">软件源</option><option value="openx_firmware">OpenX固件</option></select>
      <select className="select" value={confidence} onChange={e => setConfidence(e.target.value)}><option value="all">全部置信度</option><option value="direct">direct</option><option value="inferred">inferred</option><option value="weak">weak</option><option value="unknown">unknown</option></select>
    </div>
    <div className="grid cols-2">{filtered.map(asset => <AssetCard key={asset.id} asset={asset} onClick={() => openAsset(asset)} />)}</div>
  </div>;
}

function ThreatQueue({ model }: { model: ThreatViewModel }) {
  const [items, setItems] = useState(model.queue);
  const advance = (index: number) => {
    setItems(prev => prev.map((item, i) => {
      if (i !== index) return item;
      const status = String(item.status ?? '');
      const newStatus = status.includes('待') ? '持续跟踪' : '已关闭';
      return { ...item, status: newStatus };
    }));
  };
  if (!items.length) return <EmptyState title="暂无跟踪队列" />;
  return <div className="table-card"><table><thead><tr><th>对象</th><th>类型</th><th>优先级</th><th>状态</th><th>负责人</th><th>原因</th><th>操作</th></tr></thead><tbody>{items.map((item, index) => <tr key={index} className="clickable"><td><div className="repo-name">{String(item.name ?? item.title ?? '-')}</div></td><td>{String(item.queue_type ?? item.type ?? '-')}</td><td><span className={`badge ${String(item.priority) === 'P0' ? 'A' : 'B'}`}>{String(item.priority ?? '-')}</span></td><td>{String(item.status ?? '-')}</td><td>{String(item.assignee ?? item.owner ?? '-')}</td><td>{String(item.reason ?? '-')}</td><td><button className="btn" onClick={() => advance(index)}>推进</button></td></tr>)}</tbody></table></div>;
}

function ThreatOps({ model, kind }: { model: ThreatViewModel; kind: ViewId }) {
  if (kind === 'ops-tasks') {
    return <div className="table-card"><table><thead><tr><th>任务</th><th>状态</th><th>触发</th><th>范围</th><th>数量</th><th>说明</th></tr></thead><tbody>{opsTasks.map(t => <tr key={t.id} className="clickable"><td><div className="repo-name">{t.name}</div></td><td><span className={`badge ${t.status === '成功' ? 'A' : t.status === '运行中' ? 'B' : 'C'}`}>{t.status}</span></td><td>{t.trigger}</td><td>{t.scope}</td><td>{t.count}</td><td>{t.note}</td></tr>)}</tbody></table></div>;
  }
  if (kind === 'ops-sources') {
    return <div className="table-card"><table><thead><tr><th>数据源</th><th>类型</th><th>状态</th><th>覆盖</th><th>最近成功</th><th>说明</th></tr></thead><tbody>{opsSources.map(s => <tr key={s.id} className="clickable"><td><div className="repo-name">{s.name}</div></td><td>{s.type}</td><td><span className={`badge ${s.status === 'enabled' ? 'A' : s.status === 'cooldown' ? 'B' : 'C'}`}>{s.status}</span></td><td>{s.coverage}</td><td>{s.last}</td><td>{s.note}</td></tr>)}</tbody></table></div>;
  }
  if (kind === 'ops-rules') {
    const rules = model.opsRules ?? [];
    return <div className="grid cols-2">{rules.map(r => <Card key={r.id} className="clickable"><div className="row-title"><span className={`badge ${r.status === 'active' ? 'A' : r.status === 'caution' ? 'B' : 'C'}`}>{r.status}</span><span className="badge">{r.owner}</span></div><h3>{r.name}</h3><p>{r.note}</p></Card>)}</div>;
  }
  if (kind === 'ops-quality') {
    const qualityItems = [
      { id: 'qa-preselector-fn', severity: 'warn', title: 'PreSelector false-negative 偏高', target: '2026-06-15', note: '旧入选误拒 108/242，不能 hard reject。' },
      { id: 'qa-weak-relation', severity: 'warn', title: 'MindIE ↔ CANN/GE 弱关联', target: 'asset-mindie', note: '需要 SBOM 或 release note 证据确认。' },
      { id: 'qa-source-gap', severity: 'info', title: 'SourceAvailabilityCheck 未接入', target: 'daily shadow', note: '下一步补 6 源存在性和数量检查。' },
      { id: 'qa-cve-dup', severity: 'info', title: 'CVE 聚合可能重复', target: 'opengauss/security', note: '同一 CVE 在 issue/公告中重复出现，需要归一。' },
    ];
    return <div className="table-card"><table><thead><tr><th>质量项</th><th>级别</th><th>对象</th><th>说明</th><th>操作</th></tr></thead><tbody>{qualityItems.map(q => <tr key={q.id} className="clickable"><td><div className="repo-name">{q.title}</div></td><td><span className={`badge ${q.severity === 'warn' ? 'B' : 'C'}`}>{q.severity}</span></td><td>{q.target}</td><td>{q.note}</td><td><button className="btn">复核</button></td></tr>)}</tbody></table></div>;
  }
  if (kind === 'ops-queue') {
    const items = model.opsManualQueue ?? [];
    return <div className="table-card"><table><thead><tr><th>事项</th><th>类型</th><th>优先级</th><th>状态</th><th>操作</th></tr></thead><tbody>{items.map(q => <tr key={q.id} className="clickable"><td><div className="repo-name">{q.title}</div></td><td>{q.type}</td><td><span className={`badge ${q.priority === 'P0' ? 'A' : q.priority === 'P1' ? 'B' : 'C'}`}>{q.priority}</span></td><td>{q.status}</td><td><button className="btn">标记处理</button></td></tr>)}</tbody></table></div>;
  }
  return <EmptyState title="未知运营页面" />;
}

function RepoTable({ repos, openRepo }: { repos: ThreatRepo[]; openRepo: (repo: ThreatRepo) => void }) {
  return <table><thead><tr><th>目标</th><th>风险</th><th>攻击面</th><th>安全线索</th><th>评分拆解</th><th>操作</th></tr></thead><tbody>{repos.map(repo => <tr className="clickable" key={repo.id} onClick={() => openRepo(repo)}>
    <td><div className="repo-name">{repo.org}/{repo.name}</div><div className="repo-url">{repo.url}</div><div className="muted small">{repo.summary}</div></td>
    <td><span className={`badge ${repo.score >= 75 ? 'A' : repo.score >= 50 ? 'B' : 'C'}`}>Grade {repo.grade}</span><div style={{ height: 7 }} /><div className="score-bar"><i style={{ width: `${Math.min(100, repo.score)}%` }} /></div><div className="small muted">{Math.round(repo.score)}</div></td>
    <td><span className="badge">{repo.surface}</span></td>
    <td>CVE {repo.cve}<br />SA {repo.sa}<br />Sec items {repo.sec}<div style={{ height: 7 }} />{repo.evidence.length ? <button className="btn" onClick={(event) => { event.stopPropagation(); openRepo(repo); }}>{repo.evidence.length} 条详情</button> : <span className="muted small">暂无详情</span>}</td>
    <td><ScoreBreakdown breakdown={repo.breakdown} mini /></td>
    <td><button className="btn primary" onClick={(event) => { event.stopPropagation(); openRepo(repo); }}>详情</button><button className="btn" onClick={(event) => event.stopPropagation()}>跟踪</button></td>
  </tr>)}</tbody></table>;
}

function RepoList({ repos, openRepo, compact = false }: { repos: ThreatRepo[]; openRepo: (repo: ThreatRepo) => void; compact?: boolean }) {
  if (!repos.length) return <EmptyState title="暂无目标" />;
  return <div className={compact ? 'mini-list' : 'repo-list'}>{repos.map(repo => <button key={repo.id} onClick={() => openRepo(repo)}><strong>{repo.title}</strong><span>{repo.surface} · CVE {repo.cve} · Sec {repo.sec}</span><em>{Math.round(repo.score)}</em></button>)}</div>;
}

function AssetCard({ asset, onClick }: { asset: ThreatAsset; onClick: () => void }) {
  return <div className="card asset-card" onClick={onClick}><div className="row-title"><span className={`badge ${asset.confidence || 'C'}`}>{asset.label || asset.source}</span><span className={`badge ${asset.confidence || 'C'}`}>{asset.confidence || 'unknown'}</span></div><h3>{asset.title}</h3><p>{asset.evidence || asset.summary}</p><div className="asset-meta"><div><b>{asset.model || '-'}</b><span>型号/名称</span></div><div><b>{asset.version || '-'}</b><span>版本/tag</span></div><div><b>{asset.count || '-'}</b><span>包数量/下载量</span></div><div><b>{asset.latest || '-'}</b><span>最近更新</span></div></div><div className="split"><button className="btn primary" onClick={(e) => { e.stopPropagation(); onClick(); }}>资产详情</button><button className="btn" onClick={(e) => e.stopPropagation()}>加入跟踪</button></div></div>;
}

function AssetDrawer({ asset, onClose }: { asset: ThreatAsset | null; onClose: () => void }) {
  return <Drawer open={Boolean(asset)} title={asset?.title ?? ''} subtitle={asset ? `${asset.source} · ${asset.sourceType}` : ''} onClose={onClose}>{asset && <>
    <div className="grid cols-2"><div className="detail-card card"><h3>资产概览</h3><p>{asset.summary || '暂无摘要。'}</p><div className="asset-meta"><div><b>{asset.raw.modelName as string || asset.title}</b><span>型号/名称</span></div><div><b>{asset.raw.tag as string || asset.raw.firmwareVersion as string || '-'}</b><span>版本/tag</span></div><div><b>{asset.raw.packageCount as string || asset.raw.downloadCount as string || '-'}</b><span>规模</span></div><div><b>{asset.raw.updateTime as string || asset.raw.latestRelease as string || '-'}</b><span>更新时间</span></div></div></div><div className="detail-card card"><h3>推断关联仓库（待复核）</h3><p className="muted small">资产到代码仓关系来自命名、产品线和生态推断，需要人工复核。</p><p>当前无显式源码仓证据。</p></div></div>
    <div className="detail-card card"><h3>建议动作</h3><div className="split"><button className="btn primary">加入跟踪</button><button className="btn">加入解包</button><button className="btn">加入 SBOM</button><button className="btn warn">标记关联待复核</button></div></div>
  </>}</Drawer>;
}

function FiltersBar({ filters, setFilters, grades, surfaces }: { filters: FilterState; setFilters: (filters: FilterState) => void; grades: string[]; surfaces: string[] }) {
  return <div className="filters"><input className="search" value={filters.search} onChange={event => setFilters({ ...filters, search: event.target.value })} placeholder="搜索组织/仓库/描述" /><select className="select" value={filters.grade} onChange={event => setFilters({ ...filters, grade: event.target.value })}><option value="all">全部等级</option>{grades.map(grade => <option key={grade}>{grade}</option>)}</select><select className="select" value={filters.surface} onChange={event => setFilters({ ...filters, surface: event.target.value })}><option value="all">全部攻击面</option>{surfaces.map(surface => <option key={surface}>{surface}</option>)}</select></div>;
}

function ScoreBreakdown({ breakdown, mini = false }: { breakdown: Record<string, number>; mini?: boolean }) {
  const entries = Object.entries(breakdown ?? {}).slice(0, mini ? 5 : undefined);
  if (!entries.length) return <EmptyState title="暂无评分拆解" />;
  return <div className={mini ? 'breakdown mini' : 'breakdown'}>{entries.map(([key, value]) => <div className="break-row" key={key}><span title={key}>{scoreLabel(key)}</span><span className="bar"><i style={{ width: `${Math.min(100, Number(value) * 4)}%` }} /></span><b>{Number(value).toFixed(0)}</b></div>)}</div>;
}

function scoreLabel(key: string): string {
  return ({ attack_surface: '攻击面', cve: '历史 CVE', security_advisory: '安全公告', broad_security: '安全线索', severity: '严重性', exploit: 'Exploit', exposure: '暴露面', inherited: '继承分', language_vuln倾向: '语言风险', untrusted_input: '不可信输入', historical_cve: '历史 CVE', complexity_stars: '复杂度', security_boundary: '安全边界' } as Record<string, string>)[key] || key;
}

function EvidenceList({ items }: { items: string[] }) {
  return items.length ? <ul className="evidence-list">{items.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul> : <EmptyState title="暂无证据" />;
}

function StatsGrid({ data }: { data: Record<string, unknown> }) {
  const entries = Object.entries(data ?? {}).filter(([, value]) => typeof value === 'number' || typeof value === 'string').slice(0, 12);
  return <div className="stats-grid">{entries.map(([key, value]) => <div key={key}><span>{key}</span><strong>{String(value)}</strong></div>)}</div>;
}

function PanelTitle({ icon, title, hint }: { icon?: React.ReactNode; title: string; hint?: string }) {
  return <div className="panel-title"><div>{icon}<h3>{title}</h3></div>{hint && <span>{hint}</span>}</div>;
}

function filterRepos(repos: ThreatRepo[], filters: FilterState): ThreatRepo[] {
  const query = filters.search.trim().toLowerCase();
  return repos.filter(repo => {
    if (query && !`${repo.title} ${repo.org} ${repo.name} ${repo.surface} ${repo.url} ${repo.evidence.join(' ')}`.toLowerCase().includes(query)) return false;
    if (filters.grade !== 'all' && String(repo.grade) !== filters.grade) return false;
    if (filters.surface !== 'all' && repo.surface !== filters.surface) return false;
    if (filters.onlyCve && repo.cve <= 0) return false;
    if (filters.onlyHigh && repo.score < 75 && !repo.status.includes('高风险')) return false;
    return true;
  }).sort((a, b) => b.score - a.score);
}

function heroTitle(view: ViewId): string {
  return ({ today: '今天有哪些目标值得看', repos: '开源代码仓目标库', surface: '攻击面评分与分布', assets: '固件 / 镜像 / Hub 资产库', graph: '代码仓与资产关联图谱', queue: '威胁跟踪队列', 'ops-tasks': '采集任务', 'ops-sources': '数据源状态', 'ops-quality': '质量审计' } as Record<ViewId, string>)[view];
}

function heroCopy(view: ViewId): string {
  return ({ today: '优先呈现高风险目标、CVE/SA/security issue 和推荐挖洞方向。', repos: '搜索、过滤、排序所有华为开源仓，并查看证据链。', surface: '按语言、输入面、历史漏洞、复杂度和安全边界拆分评分。', assets: '查看 firmware、AscendHub、mirror、OpenX Huawei 等资产线索。', graph: '用轻量关系图查看组织、仓库、CVE、攻击面和资产。', queue: '承接待研判、待代码审计、持续跟踪等行动项。', 'ops-tasks': '查看威胁 pipeline 运行结果和报告 artifact。', 'ops-sources': '查看 CVE scout、攻击面和报告数据源。', 'ops-quality': '查看质量审计与覆盖率提示。' } as Record<ViewId, string>)[view];
}

function navCount(view: ViewId, model: ThreatViewModel | null): string {
  if (!model) return '—';
  return ({
    today: String(model.today.length),
    repos: String(model.summary.totalRepos || model.repos.length),
    surface: String(Object.keys(groupBy(model.repos, repo => repo.surface || 'unknown')).length),
    assets: String(model.assets.length),
    graph: String(model.graph.nodes.length),
    queue: String(model.queue.length),
    'ops-tasks': String(model.summary.totalRepos),
    'ops-sources': String(Object.keys(model.summary.sourceStats).length),
    'ops-quality': String(Object.keys(model.summary.scanModes).length)
  } as Record<ViewId, string>)[view];
}

function navMeta(view: ViewId): string {
  return ({ today: 'Today', repos: 'Repo', surface: 'Surface', assets: 'Asset', graph: 'Graph', queue: 'Track', 'ops-tasks': 'Jobs', 'ops-sources': 'Sources', 'ops-quality': 'QA' } as Record<ViewId, string>)[view];
}

function unique(values: string[]): string[] { return Array.from(new Set(values)).filter(Boolean).sort(); }
function groupBy<T>(items: T[], keyFn: (item: T) => string): Record<string, T[]> { return items.reduce<Record<string, T[]>>((acc, item) => { const key = keyFn(item); acc[key] = acc[key] ?? []; acc[key].push(item); return acc; }, {}); }
function avg(values: number[]): number { return values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0; }
