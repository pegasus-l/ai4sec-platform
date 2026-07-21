import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { AlertTriangle, Boxes, GitBranch, GitFork, Network, Radar, ShieldCheck, Target, Workflow } from 'lucide-react';
import { fetchFrontendContract } from '../../api/frontendContract';
import { Badge, Card, Drawer, EmptyState, MetricCard } from '../../components/ui';
import type { ThreatAsset, ThreatRepo, ThreatViewModel } from '../../types/threat';
import { adaptThreatContract } from './threatAdapters';

type ViewId = 'today' | 'repos' | 'surface' | 'assets' | 'graph' | 'queue' | 'ops-tasks' | 'ops-sources' | 'ops-quality';

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
    { id: 'ops-quality', icon: '◈', title: '质量审计' }
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
  const [selectedRepo, setSelectedRepo] = useState<ThreatRepo | null>(null);
  const [selectedAsset, setSelectedAsset] = useState<ThreatAsset | null>(null);
  const { data, isLoading, error } = useQuery({ queryKey: ['frontend-contract'], queryFn: fetchFrontendContract });
  const model = useMemo(() => data ? adaptThreatContract(data) : null, [data]);

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
        <div className="head-actions">{view === 'repos' && model ? <FiltersBar filters={filters} setFilters={setFilters} grades={repoGrades} surfaces={repoSurfaces} /> : <><button className="btn primary" onClick={() => location.reload()}>刷新数据</button><a className="btn" href="/api/threats/reports" target="_blank">查看报告 API</a></>}</div>
      </section>
      <div className="content-body view">
        {isLoading && <EmptyState title="正在加载威胁洞察数据" description="从 /api/frontend/v9 拉取统一契约。" />}
        {error && <EmptyState title="加载失败" description={(error as Error).message} />}
        {model && renderView(view, model, visibleRepos, filters, setFilters, setSelectedRepo, setSelectedAsset)}
      </div>
    </section>
    <RepoDrawer repo={selectedRepo} onClose={() => setSelectedRepo(null)} />
    <AssetDrawer asset={selectedAsset} onClose={() => setSelectedAsset(null)} />
  </main>;
}

function renderView(view: ViewId, model: ThreatViewModel, repos: ThreatRepo[], filters: FilterState, setFilters: (filters: FilterState) => void, openRepo: (repo: ThreatRepo) => void, openAsset: (asset: ThreatAsset) => void) {
  if (view === 'today') return <ThreatToday model={model} openRepo={openRepo} />;
  if (view === 'repos') return <ThreatRepos model={model} repos={repos} filters={filters} setFilters={setFilters} openRepo={openRepo} />;
  if (view === 'surface') return <ThreatSurface model={model} openRepo={openRepo} />;
  if (view === 'assets') return <ThreatAssets model={model} openAsset={openAsset} />;
  if (view === 'graph') return <ThreatGraph model={model} openRepo={openRepo} openAsset={openAsset} />;
  if (view === 'queue') return <ThreatQueue model={model} />;
  return <ThreatOps model={model} kind={view} />;
}

function ThreatToday({ model, openRepo }: { model: ThreatViewModel; openRepo: (repo: ThreatRepo) => void }) {
  const { summary } = model;
  const focus = model.today.slice(0, 4);
  return <div className="grid">
    <div className="grid cols-4">
      <MetricCard label="A级/高风险仓库" value={summary.highRisk} hint="点击代码仓可筛选高风险目标" tone="red" />
      <MetricCard label="安全线索项目" value={summary.withCve} hint="命中过 CVE / SA / security issue" tone="amber" />
      <MetricCard label="资产变化" value={summary.assets} hint="固件/镜像/Hub/OpenX 资产条目" tone="green" />
      <MetricCard label="CVE / SA" value={`${summary.uniqueCve}/${summary.totalSa}`} hint={`${summary.totalCve} 条 CVE 记录`} tone="sky" />
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

function ThreatSurface({ model, openRepo }: { model: ThreatViewModel; openRepo: (repo: ThreatRepo) => void }) {
  const bySurface = groupBy(model.repos, repo => repo.surface || 'unknown');
  const sorted = Object.entries(bySurface).sort((a, b) => b[1].length - a[1].length);
  const totalRepos = model.repos.length;
  const totalCve = model.repos.reduce((sum, repo) => sum + repo.cve, 0);
  const totalSec = model.repos.reduce((sum, repo) => sum + repo.sec, 0);
  const selected = sorted[0];
  const selectedRepos = selected?.[1] ?? [];
  return <div className="grid">
    <div className="grid cols-3">
      <MetricCard label="相关代码仓" value={totalRepos} hint="当前目标库口径" tone="sky" />
      <MetricCard label="CVE 总量" value={totalCve} hint="所有攻击面累计" tone="amber" />
      <MetricCard label="安全线索" value={totalSec} hint="CVE / SA / issue 合计" tone="green" />
    </div>
    <div className="grid cols-2">
      <Card><h3>攻击面总览</h3><p className="muted small">点击攻击面查看代表仓库；需要仓库明细时进入代码仓页面。</p><div className="surface-matrix">{sorted.map(([surface, items]) => { const cve = items.reduce((sum, repo) => sum + repo.cve, 0); const high = items.filter(repo => repo.score >= 75).length; return <button key={surface} className="surface-matrix-item clickable" onClick={() => items[0] && openRepo(items[0])}><div className="row-title"><span><b>◈ {surface}</b></span><span className="badge C">查看</span></div><p className="muted small">平均风险 {Math.round(avg(items.map(item => item.score)))}，代表攻击面目标 {items[0]?.org}/{items[0]?.name}</p><div className="split"><span className="badge">代码仓 {items.length}</span><span className="badge">A级 {high}</span><span className="badge">CVE {cve}</span></div><div className="score-bar" style={{ marginTop: 9 }}><i style={{ width: `${Math.min(100, Math.round(items.length / Math.max(1, totalRepos) * 300))}%` }} /></div></button>; })}</div></Card>
      <div className="grid"><Card className="detail-card"><h3>{selected?.[0] ?? '攻击面'} 聚合指标</h3><p>该攻击面下共有 {selectedRepos.length} 个目标，平均风险 {Math.round(avg(selectedRepos.map(item => item.score)))}。</p><div className="asset-meta"><div><b>{selectedRepos.length}</b><span>相关代码仓</span></div><div><b>{selectedRepos.filter(repo => repo.score >= 75).length}</b><span>A/高风险仓库</span></div><div><b>{selectedRepos.reduce((sum, repo) => sum + repo.cve, 0)}</b><span>CVE</span></div><div><b>{selectedRepos.reduce((sum, repo) => sum + repo.sec, 0)}</b><span>安全线索</span></div></div></Card><Card><h3>该攻击面的代码仓样例</h3><RepoList repos={selectedRepos.slice(0, 8)} openRepo={openRepo} compact /></Card></div>
    </div>
  </div>;
}

function ThreatAssets({ model, openAsset }: { model: ThreatViewModel; openAsset: (asset: ThreatAsset) => void }) {
  const bySource = groupBy(model.assets, asset => asset.source);
  return <div className="view-stack">
    <div className="metric-grid">{Object.entries(bySource).map(([source, items]) => <MetricCard key={source} label={source} value={items.length} hint="资产条目" tone="violet" />)}</div>
    <div className="asset-grid">{model.assets.map(asset => <AssetCard key={asset.id} asset={asset} onClick={() => openAsset(asset)} />)}</div>
  </div>;
}

function ThreatGraph({ model, openRepo, openAsset }: { model: ThreatViewModel; openRepo: (repo: ThreatRepo) => void; openAsset: (asset: ThreatAsset) => void }) {
  const orgs = Object.entries(groupBy(model.repos, repo => repo.org)).sort((a, b) => b[1].length - a[1].length).slice(0, 10);
  const assetGroups = Object.entries(groupBy(model.assets, asset => asset.source)).sort((a, b) => b[1].length - a[1].length);
  return <div className="graph-layout">
    <div className="graph-wrap">
      <div className="tree-column repo-tree"><h3>代码仓生态</h3>{orgs.map(([org, repos]) => <div className="tree-group" key={org}><div className="tree-group-title">{org}<span>{repos.length}</span></div>{repos.slice(0, 8).map(repo => <button key={repo.id} className="tree-node-row" onClick={() => openRepo(repo)}><span className="node-icon">◎</span><span><span className="node-title">{repo.name}</span><span className="node-count">{repo.surface} · score {Math.round(repo.score)}</span></span></button>)}</div>)}</div>
      <div className="tree-column asset-tree"><h3>资产侧</h3>{assetGroups.map(([source, assets]) => <div className="tree-group" key={source}><div className="tree-group-title">{source}<span>{assets.length}</span></div>{assets.slice(0, 10).map(asset => <button key={asset.id} className="tree-node-row" onClick={() => openAsset(asset)}><span className="node-icon">▣</span><span><span className="node-title">{asset.title}</span><span className="node-count">{asset.sourceType}</span></span></button>)}</div>)}</div>
    </div>
    <aside className="graph-side"><Card><h3>使用方式</h3><p className="muted small">图谱不是主导航入口，而是目标库里的视图模式：先看列表排序，再用图谱理解组织、仓库、CVE、固件和镜像之间的关系。</p><div className="relation-note">当前关系由命名、产品线和资产文本推断，弱关联需要人工复核。</div></Card><Card><h3>图谱统计</h3><div className="asset-meta"><div><b>{model.repos.length}</b><span>仓库节点</span></div><div><b>{model.assets.length}</b><span>资产节点</span></div><div><b>{model.summary.uniqueCve}</b><span>CVE</span></div><div><b>{model.summary.broadSecurity}</b><span>安全线索</span></div></div></Card></aside>
  </div>;
}

function ThreatQueue({ model }: { model: ThreatViewModel }) {
  return <Card><PanelTitle icon={<Workflow />} title="跟踪队列" hint="人工复核 / 持续跟踪" /> {model.queue.length ? <table className="data-table"><thead><tr><th>类型</th><th>优先级</th><th>状态</th><th>原因</th></tr></thead><tbody>{model.queue.map((item, index) => <tr key={index}><td>{String(item.queue_type ?? item.name ?? '-')}</td><td>{String(item.priority ?? '-')}</td><td>{String(item.status ?? '-')}</td><td>{String(item.reason ?? '-')}</td></tr>)}</tbody></table> : <EmptyState title="暂无跟踪队列" />}</Card>;
}

function ThreatOps({ model, kind }: { model: ThreatViewModel; kind: ViewId }) {
  const data = kind === 'ops-quality' ? model.cveScout : kind === 'ops-sources' ? model.attackSurface : model.reports;
  return <Card><PanelTitle icon={<Boxes />} title="运营数据" hint={kind} /><pre className="json-preview">{JSON.stringify(data, null, 2).slice(0, 6000)}</pre></Card>;
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
  return <button className="asset-card" onClick={onClick}><span className="label">{asset.source}</span><strong>{asset.title}</strong><p>{asset.summary || asset.sourceType}</p><div><Badge tone="violet">{asset.sourceType}</Badge>{asset.score > 0 && <Badge tone="amber">{Math.round(asset.score)}</Badge>}</div></button>;
}

function RepoDrawer({ repo, onClose }: { repo: ThreatRepo | null; onClose: () => void }) {
  return <Drawer open={Boolean(repo)} title={repo?.title ?? ''} subtitle={repo?.url} onClose={onClose}>{repo && <div className="drawer-grid"><MetricCard label="风险分" value={Math.round(repo.score)} tone="red" /><MetricCard label="CVE/SA/Sec" value={`${repo.cve}/${repo.sa}/${repo.sec}`} tone="amber" /><MetricCard label="攻击面" value={repo.surface} tone="sky" /><MetricCard label="Stars" value={repo.stars} tone="green" /><Card><PanelTitle title="评分拆解" /><ScoreBreakdown breakdown={repo.breakdown} /></Card><Card><PanelTitle title="证据链" /><EvidenceList items={repo.evidence} /></Card><Card><PanelTitle title="研判原因" /><EvidenceList items={repo.reasons} /></Card><Card><PanelTitle title="原始字段" /><pre className="json-preview">{JSON.stringify(repo.raw, null, 2).slice(0, 5000)}</pre></Card></div>}</Drawer>;
}

function AssetDrawer({ asset, onClose }: { asset: ThreatAsset | null; onClose: () => void }) {
  return <Drawer open={Boolean(asset)} title={asset?.title ?? ''} subtitle={asset?.source} onClose={onClose}>{asset && <div className="drawer-grid"><MetricCard label="来源" value={asset.source} tone="violet" /><MetricCard label="状态" value={asset.status} tone="green" /><Card><PanelTitle title="资产说明" /><p>{asset.summary || '暂无摘要。'}</p>{asset.url && <a href={asset.url} target="_blank" rel="noreferrer">打开来源</a>}</Card><Card><PanelTitle title="原始字段" /><pre className="json-preview">{JSON.stringify(asset.raw, null, 2).slice(0, 6000)}</pre></Card></div>}</Drawer>;
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
