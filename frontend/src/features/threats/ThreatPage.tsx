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

  return <div className="workspace">
    <aside className="sidebar">
      <div className="domain-card"><span className="label">THREAT INTEL</span><strong>开源威胁洞察</strong><p>从代码仓、CVE/SA、攻击面和资产关系中筛选值得挖的目标。</p></div>
      {navGroups.map(group => <div className="nav-group" key={group.title}><h4>{group.title}</h4>{group.items.map(item => <button key={item.id} className={view === item.id ? 'active' : ''} onClick={() => setView(item.id)}><span>{item.icon}</span>{item.title}</button>)}</div>)}
    </aside>
    <main className="content">
      <section className="hero">
        <div><span className="label">{activeTitle}</span><h1>{heroTitle(view)}</h1><p>{heroCopy(view)}</p></div>
        <div className="hero-actions"><button onClick={() => location.reload()}>刷新数据</button><a href="/api/threats/reports" target="_blank">查看报告 API</a></div>
      </section>
      {isLoading && <EmptyState title="正在加载威胁洞察数据" description="从 /api/frontend/v9 拉取统一契约。" />}
      {error && <EmptyState title="加载失败" description={(error as Error).message} />}
      {model && renderView(view, model, visibleRepos, filters, setFilters, setSelectedRepo, setSelectedAsset)}
    </main>
    <RepoDrawer repo={selectedRepo} onClose={() => setSelectedRepo(null)} />
    <AssetDrawer asset={selectedAsset} onClose={() => setSelectedAsset(null)} />
  </div>;
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
  return <div className="view-stack">
    <div className="metric-grid">
      <MetricCard label="代码仓" value={summary.totalRepos.toLocaleString()} hint="本次 connector 输入" tone="sky" />
      <MetricCard label="高风险目标" value={summary.highRisk} hint="score ≥ 75 / 高风险状态" tone="red" />
      <MetricCard label="CVE / SA" value={`${summary.uniqueCve} / ${summary.totalSa}`} hint={`${summary.totalCve} 条 CVE 记录`} tone="amber" />
      <MetricCard label="资产" value={summary.assets} hint="固件 / Hub / Mirror / OpenX" tone="green" />
    </div>
    <div className="split-grid">
      <Card><PanelTitle icon={<Radar />} title="推荐挖洞目标" hint="按风险分排序" /> <RepoList repos={model.today.slice(0, 8)} openRepo={openRepo} compact /></Card>
      <Card><PanelTitle icon={<ShieldCheck />} title="CVE Scout 概览" hint="安全线索来源" /> <StatsGrid data={{ ...summary.sourceStats, ...summary.scanModes }} /></Card>
    </div>
  </div>;
}

function ThreatRepos({ model, repos, filters, setFilters, openRepo }: { model: ThreatViewModel; repos: ThreatRepo[]; filters: FilterState; setFilters: (filters: FilterState) => void; openRepo: (repo: ThreatRepo) => void }) {
  const grades = unique(model.repos.map(repo => repo.grade).filter(Boolean));
  const surfaces = unique(model.repos.map(repo => repo.surface).filter(Boolean));
  return <div className="view-stack">
    <Card><PanelTitle icon={<Target />} title="目标库" hint={`${repos.length}/${model.repos.length} 个目标`} /><FiltersBar filters={filters} setFilters={setFilters} grades={grades} surfaces={surfaces} /><RepoTable repos={repos} openRepo={openRepo} /></Card>
  </div>;
}

function ThreatSurface({ model, openRepo }: { model: ThreatViewModel; openRepo: (repo: ThreatRepo) => void }) {
  const bySurface = groupBy(model.repos, repo => repo.surface || 'unknown');
  const sorted = Object.entries(bySurface).sort((a, b) => b[1].length - a[1].length);
  return <div className="view-stack">
    <div className="split-grid surface-layout">
      <Card><PanelTitle icon={<Network />} title="攻击面分布" hint="按目标数量统计" /> <div className="surface-list">{sorted.map(([surface, items]) => <button key={surface} onClick={() => items[0] && openRepo(items[0])}><strong>{surface}</strong><span>{items.length} 个目标</span><em>{Math.round(avg(items.map(item => item.score)))} avg</em></button>)}</div></Card>
      <Card><PanelTitle icon={<AlertTriangle />} title="A/B 高价值项目" hint="攻击面评分 Top" /> <RepoList repos={model.repos.filter(repo => ['A', 'B', '高', '严重'].includes(String(repo.grade))).slice(0, 12)} openRepo={openRepo} compact /></Card>
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
  return <Card className="graph-card"><PanelTitle icon={<GitFork />} title="关联图谱" hint="组织 / 仓库 / CVE / 攻击面 / 资产" /><div className="graph-canvas">{model.graph.nodes.slice(0, 90).map((node, index) => <button key={node.id} className={`graph-node graph-${node.type}`} style={{ left: `${8 + (index * 17) % 82}%`, top: `${10 + (index * 29) % 76}%` }} onClick={() => { const repo = model.repos.find(item => `repo:${item.id}` === node.id); const asset = model.assets.find(item => `asset:${item.id}` === node.id); if (repo) openRepo(repo); if (asset) openAsset(asset); }}><span>{node.label}</span>{node.score != null && <em>{Math.round(node.score)}</em>}</button>)}</div></Card>;
}

function ThreatQueue({ model }: { model: ThreatViewModel }) {
  return <Card><PanelTitle icon={<Workflow />} title="跟踪队列" hint="人工复核 / 持续跟踪" /> {model.queue.length ? <table className="data-table"><thead><tr><th>类型</th><th>优先级</th><th>状态</th><th>原因</th></tr></thead><tbody>{model.queue.map((item, index) => <tr key={index}><td>{String(item.queue_type ?? item.name ?? '-')}</td><td>{String(item.priority ?? '-')}</td><td>{String(item.status ?? '-')}</td><td>{String(item.reason ?? '-')}</td></tr>)}</tbody></table> : <EmptyState title="暂无跟踪队列" />}</Card>;
}

function ThreatOps({ model, kind }: { model: ThreatViewModel; kind: ViewId }) {
  const data = kind === 'ops-quality' ? model.cveScout : kind === 'ops-sources' ? model.attackSurface : model.reports;
  return <Card><PanelTitle icon={<Boxes />} title="运营数据" hint={kind} /><pre className="json-preview">{JSON.stringify(data, null, 2).slice(0, 6000)}</pre></Card>;
}

function RepoTable({ repos, openRepo }: { repos: ThreatRepo[]; openRepo: (repo: ThreatRepo) => void }) {
  return <table className="data-table repo-table"><thead><tr><th>仓库</th><th>组织</th><th>风险</th><th>攻击面</th><th>CVE/SA/Sec</th><th>状态</th></tr></thead><tbody>{repos.map(repo => <tr key={repo.id} onClick={() => openRepo(repo)}><td><strong>{repo.name}</strong><small>{repo.url}</small></td><td>{repo.org}</td><td><span className="score-pill">{Math.round(repo.score)}</span></td><td>{repo.surface}</td><td>{repo.cve}/{repo.sa}/{repo.sec}</td><td><Badge tone={repo.status.includes('高风险') ? 'red' : repo.filtered ? 'slate' : 'amber'}>{repo.status}</Badge></td></tr>)}</tbody></table>;
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
  return <div className="filters"><input value={filters.search} onChange={event => setFilters({ ...filters, search: event.target.value })} placeholder="搜索组织 / 仓库 / 攻击面 / CVE" /><select value={filters.grade} onChange={event => setFilters({ ...filters, grade: event.target.value })}><option value="all">全部等级</option>{grades.map(grade => <option key={grade}>{grade}</option>)}</select><select value={filters.surface} onChange={event => setFilters({ ...filters, surface: event.target.value })}><option value="all">全部攻击面</option>{surfaces.map(surface => <option key={surface}>{surface}</option>)}</select><label><input type="checkbox" checked={filters.onlyCve} onChange={event => setFilters({ ...filters, onlyCve: event.target.checked })} /> 有 CVE</label><label><input type="checkbox" checked={filters.onlyHigh} onChange={event => setFilters({ ...filters, onlyHigh: event.target.checked })} /> 高风险</label></div>;
}

function ScoreBreakdown({ breakdown }: { breakdown: Record<string, number> }) {
  const entries = Object.entries(breakdown ?? {});
  if (!entries.length) return <EmptyState title="暂无评分拆解" />;
  return <div className="breakdown">{entries.map(([key, value]) => <div key={key}><span>{key}</span><strong>{Number(value).toFixed(1)}</strong><i style={{ width: `${Math.min(100, Number(value))}%` }} /></div>)}</div>;
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

function unique(values: string[]): string[] { return Array.from(new Set(values)).filter(Boolean).sort(); }
function groupBy<T>(items: T[], keyFn: (item: T) => string): Record<string, T[]> { return items.reduce<Record<string, T[]>>((acc, item) => { const key = keyFn(item); acc[key] = acc[key] ?? []; acc[key].push(item); return acc; }, {}); }
function avg(values: number[]): number { return values.length ? values.reduce((a, b) => a + b, 0) / values.length : 0; }
