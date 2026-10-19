import { useEffect, useState, type ReactNode } from 'react';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Badge, EmptyState } from '../../components/ui';
import { useToast } from '../../components/Toast';
import { addCase, addCaseSource, deleteCaseSource, fetchCases, fetchCaseSources, fetchCaseStats, setCaseSourceEnabled } from '../../api/vulnerabilities';
import { ContextDots, invalidateCase, openCaseDrawer, severityTone, type DrawerSetter } from './CaseDrawer';
import type { CaseIdKind, CasePayload, CaseSourceTarget } from '../../types/vulnerability';

// 案例库每页条数。与素材库一样是**服务端分页**: 关键词/筛选/页码全部下推 SQL —— 库是 15.5GB 量级,
// 拉全量回前端筛就是素材库当年"分数最低那批永远不可达"的翻版。
const PAGE_SIZE = 20;

/** 与 VulnerabilityPage 同款的 KPI 网格(那边的是页面私有函数, 不导出)。 */
function MetricGrid({ items }: { items: Array<[string, ReactNode, string, 'sky' | 'green' | 'amber' | 'red' | 'violet']> }) {
  return <div className="metric-grid">{items.map(([label, value, hint, tone]) => <div className={`insight-metric metric-bg-${tone}`} key={label}><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-hint">{hint}</div></div>)}</div>;
}

const ID_KIND_LABELS: Array<[CaseIdKind | 'all', string]> = [['all', '全部'], ['cve', 'CVE'], ['ghsa', 'GHSA'], ['osv', 'OSV'], ['oss', '开源项目'], ['custom', '人工登记']];
const COMPLETENESS_LABELS: Array<[string, string]> = [['all', '全部'], ['full', '已收全'], ['partial', '收集中'], ['empty', '仅元数据']];

const CASE_KIND_TONE: Record<string, 'red' | 'violet' | 'sky' | 'amber' | 'slate'> = { cve: 'red', ghsa: 'violet', osv: 'sky', oss: 'amber', custom: 'slate' };

export function CasesView({ search, setDrawer, onOpenMaterial }: { search: string; setDrawer: DrawerSetter; onOpenMaterial?: (itemId: number) => void }) {
  const [idKind, setIdKind] = useState<string>('all');
  const [completeness, setCompleteness] = useState<string>('all');
  const [severity, setSeverity] = useState<string>('');
  const [offset, setOffset] = useState(0);
  // 搜索词防抖 250ms: 列表在服务端, 每敲一个字发一次请求会把这台机器的慢查询叠起来
  // (素材库那几个接口服务端自己就要 3.4~7.7s, 这条链路共用同一个进程)。
  const [q, setQ] = useState(search);
  useEffect(() => {
    const timer = setTimeout(() => setQ(search), 250);
    return () => clearTimeout(timer);
  }, [search]);
  // 换筛选/换搜索词必须回到第一页 —— 否则会在新结果集里停在越界的 offset 上, 页面看着像"空了"。
  useEffect(() => { setOffset(0); }, [q, idKind, completeness, severity]);

  const list = useQuery({
    queryKey: ['vulnerabilities', 'cases', { q, idKind, completeness, severity, offset }],
    queryFn: () => fetchCases({
      q, severity,
      id_kind: idKind === 'all' ? '' : idKind,
      completeness: completeness === 'all' ? '' : completeness,
      limit: PAGE_SIZE, offset,
    }),
    refetchInterval: 30_000,
    // 翻页/换筛选时保留上一页, 避免闪一屏空态(隧道上每次请求约 0.7s 固定开销)。
    placeholderData: keepPreviousData,
  });
  const stats = useQuery({ queryKey: ['vulnerabilities', 'cases', 'stats'], queryFn: fetchCaseStats, refetchInterval: 30_000 });

  const items = list.data?.items ?? [];
  const total = list.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const hasFilter = Boolean(q.trim() || idKind !== 'all' || completeness !== 'all' || severity);
  const kpi = stats.data;

  // 首次加载必须先说"在加载": 未到达时 items 是 [], 直接落到空态会看起来像"案例全没了"。
  if (list.isLoading) return <EmptyState title="正在加载漏洞案例库…" description="正在从平台读取案例列表，请稍候。" />;
  return <div className="v11-view">
    <MetricGrid items={[
      ['库内漏洞案例', kpi?.total ?? total, '一个洞一行（CVE / GHSA / 开源项目 bug），不再是从素材聚合出的主题', 'violet'],
      ['人工添加', kpi?.manual ?? 0, '人工指定的 ID 或完全手填的洞', 'sky'],
      ['上下文收全', kpi?.context.full ?? 0, '元数据 + 补丁 + 漏洞点 + 数据流四项齐备', 'green'],
      ['仅元数据', kpi?.context.empty ?? 0, '还没抓到补丁与代码，采集步会持续回溯补齐', 'amber'],
    ]} />

    <CaseAddForm />

    {/* 4 位完整度是领导那句"上下文收集全"的可见进度条: 每一格都是一个真实的采集动作的产出 */}
    <section className="panel case-progress">
      <div className="panel-head"><h3>上下文收集进度</h3><span>元数据来自 NVD/OSV，补丁来自修复 commit，漏洞点与数据流由模型从代码里抽</span></div>
      <div className="panel-body">
        <div className="progress-grid">
          {([
            ['元数据', kpi?.context.metadata ?? 0, '标题 / 严重性 / CVSS'],
            ['补丁 diff', kpi?.context.patch ?? 0, '修复 commit 的改动'],
            ['漏洞点', kpi?.context.vuln_site ?? 0, '文件 + 函数 + 行号'],
            ['数据流', kpi?.context.dataflow ?? 0, 'source → sink 每一跳'],
          ] as Array<[string, number, string]>).map(([label, count, hint]) => {
            const ratio = kpi?.total ? Math.round(count / kpi.total * 100) : 0;
            return <div className="progress-item" key={label}><div className="progress-item-head"><b>{label}</b><span>{count} / {kpi?.total ?? 0}</span></div><div className="progress"><span style={{ width: `${ratio}%` }} /></div><p className="small">{hint}</p></div>;
          })}
        </div>
      </div>
    </section>

    <div className="viewbar">
      <div className="view-pills">{ID_KIND_LABELS.map(([id, label]) => <button key={id} className={`view-pill ${idKind === id ? 'active' : ''}`} onClick={() => setIdKind(id)}>{label}</button>)}</div>
      <div className="view-pills">{COMPLETENESS_LABELS.map(([id, label]) => <button key={id} className={`view-pill ${completeness === id ? 'active' : ''}`} onClick={() => setCompleteness(id)}>{label}</button>)}</div>
      <select value={severity} onChange={event => setSeverity(event.target.value)}>
        <option value="">全部严重性</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
    </div>

    <section className="panel">
      <div className="panel-head"><h3>漏洞案例</h3><span>一条案例 = 一个洞；素材是它的证据，上下文是它的细节</span></div>
      <div className="panel-body">
        {items.length
          ? <div className="case-list">{items.map(item => <CaseCard key={item.id} item={item} onOpen={() => openCaseDrawer(item, setDrawer, onOpenMaterial)} />)}</div>
          : <EmptyState title={hasFilter ? '没有匹配的漏洞案例' : '案例库还是空的'} description={hasFilter ? '换个关键词或把筛选放宽试试。' : '每晚的采集跑批会自动登记新公开的洞；也可以在上面「添加」一个指定的 CVE / GHSA，或完全手填一个项目内部 bug。'} />}
      </div>
    </section>

    <Pagination page={page} pages={pages} total={total} setOffset={setOffset} />

    {/* 追加在页面末尾(2026-10-19):「案例从哪来」的长期配置, 与上面的案例列表是两件事 ——
        列表是结果, 这里是采集入口。 */}
    <CaseSourcesPanel />
  </div>;
}

const CASE_SOURCE_KINDS: Array<[CaseSourceTarget['kind'], string, string, string]> = [
  ['tracked_package', '生态包', 'pkg:pypi/django', '每晚按 OSV 查这个包最近公开的漏洞并登记（不传版本 = 全部已知洞）'],
  ['tracked_repo', '单个 Git 仓', 'github:apache/logging-log4j2', '拉默认分支最近几个提交，按 commit 查 OSV —— 只有被 OSV 收录了 GIT 区间的项目（多为 OSS-Fuzz）查得到'],
  ['manual_id', '指定漏洞 ID', 'CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q', 'CVE 交给当晚的 NVD 采集补元数据，GHSA / OSV 直接查 OSV'],
];

/**
 * 「我要盯哪些源」。这张表从 P1 就建好了, 但一直没入口、采集步也没消费 —— 2026-10-19 接上:
 * 每天 04:00 的采集跑批先按这里查一遍(ConsumeCaseSourcesStep), 查到的洞进上面的案例库。
 * 停用的行留在列表里(与人工关键词同一语义), 只是不参与采集。
 */
function CaseSourcesPanel() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<CaseSourceTarget['kind']>('tracked_package');
  const [identifier, setIdentifier] = useState('');
  const [label, setLabel] = useState('');
  const sources = useQuery({ queryKey: ['vulnerabilities', 'case-sources'], queryFn: fetchCaseSources, refetchInterval: 60_000 });
  const refresh = () => void qc.invalidateQueries({ queryKey: ['vulnerabilities', 'case-sources'] });
  const items = sources.data?.items ?? [];
  const kindMeta = CASE_SOURCE_KINDS.find(([id]) => id === kind)!;

  const add = useMutation({
    mutationFn: () => addCaseSource({ kind, identifier: identifier.trim(), label: label.trim() }),
    onSuccess: result => {
      toast(result.created ? `已加入盯源：${result.source.identifier}（下一轮采集生效）` : `该源已存在，已重新启用：${result.source.identifier}`, 'success');
      setIdentifier('');
      setLabel('');
      refresh();
    },
    onError: error => toast(`添加失败(${error})：请按占位符的格式填写`, 'error'),
  });
  const toggle = useMutation({
    mutationFn: ({ item, enabled }: { item: CaseSourceTarget; enabled: boolean }) => setCaseSourceEnabled(item.id, enabled),
    onSuccess: result => { toast(result.enabled ? `已启用：${result.identifier}` : `已停用：${result.identifier}`, 'success'); refresh(); },
    onError: error => toast(`操作失败(${error})`, 'error'),
  });
  const remove = useMutation({
    mutationFn: (id: number) => deleteCaseSource(id),
    onSuccess: () => { toast('已删除盯源', 'success'); refresh(); },
    onError: error => toast(`删除失败(${error})`, 'error'),
  });
  const askRemove = async (item: CaseSourceTarget) => {
    const ok = await confirm(`确认删除盯源「${item.label || item.identifier}」?\n删除后下一轮采集不再查它(想保留记录的话停用即可)。`);
    if (ok) remove.mutate(item.id);
  };

  return <section className="panel case-add">
    <div className="panel-head">
      <h3>跟踪的漏洞源</h3>
      <span>登记要长期盯的包 / 仓 / ID；每天 04:00 的采集跑批先按这里查，查到的洞自动进案例库</span>
      <button className="btn" onClick={() => setOpen(value => !value)}>{open ? '收起' : '+ 添加盯源'}</button>
    </div>
    {open && <div className="panel-body">
      <div className="view-pills case-add-modes">
        {CASE_SOURCE_KINDS.map(([id, text]) => <button key={id} className={`view-pill ${kind === id ? 'active' : ''}`} onClick={() => setKind(id)}>{text}</button>)}
      </div>
      <p className="muted small">{kindMeta[3]}</p>
      <div className="filters">
        <input className="search" placeholder={kindMeta[2]} value={identifier} onChange={event => setIdentifier(event.target.value)} onKeyDown={event => { if (event.key === 'Enter' && identifier.trim()) add.mutate(); }} />
        <input className="search" placeholder="备注（可空，如：我司使用的组件）" value={label} onChange={event => setLabel(event.target.value)} />
        <button className="btn primary" disabled={!identifier.trim() || add.isPending} onClick={() => add.mutate()}>{add.isPending ? '提交中…' : '加入盯源'}</button>
      </div>
      <p className="muted small" style={{ marginTop: 8 }}>生态名要写对（PyPI / npm / Maven / Go / crates.io / Packagist / NuGet / RubyGems 等）。重复添加不会插新行，只会把已有的那条重新启用。</p>
    </div>}
    <div className="panel-body">
      {sources.isLoading
        ? <p className="muted small">加载中…</p>
        : items.length
          ? <div className="timeline">
            {items.map(item => <div key={item.id} className="timeline-item">
              <div className="row-title">
                <span style={item.enabled ? undefined : { opacity: 0.5, textDecoration: 'line-through' }}>
                  <Badge tone={item.kind === 'tracked_package' ? 'sky' : item.kind === 'tracked_repo' ? 'amber' : 'violet'}>{CASE_SOURCE_KINDS.find(([id]) => id === item.kind)?.[1] ?? item.kind}</Badge>
                  <b style={{ marginLeft: 6 }}>{item.identifier}</b>
                  {item.label ? <span className="muted small"> · {item.label}</span> : null}
                </span>
                <span>
                  <span className={`badge ${item.enabled ? 'success' : 'warn'}`}>{item.enabled ? '启用' : '已停用'}</span>
                  <button className="btn sm" style={{ marginLeft: 6 }} disabled={toggle.isPending} onClick={() => toggle.mutate({ item, enabled: !item.enabled })}>{item.enabled ? '停用' : '启用'}</button>
                  <button className="btn sm" style={{ marginLeft: 6 }} disabled={remove.isPending} onClick={() => void askRemove(item)}>删除</button>
                </span>
              </div>
              <span className="muted small">添加人:{item.created_by || '未知'} · 添加于 {item.created_at?.slice(0, 19) || '未知'}</span>
            </div>)}
          </div>
          : <p className="muted small">还没有盯源。加上之后，每天 04:00 的采集会先查它们；想立刻验证可以先按 ID 在「添加漏洞案例」里加一个。</p>}
    </div>
  </section>;
}

/** 案例卡片: 主键徽章 + 严重性 + 4 格完整度 + 关联素材数 —— "这条洞收全了没有"一行看完。 */
function CaseCard({ item, onOpen }: { item: CasePayload; onOpen: () => void }) {
  const cves = item.cve_ids.length ? item.cve_ids : [item.canonical_id];
  return <article className="case-card clickable" onClick={onOpen}>
    <div className="case-card-main">
      <div className="badges">
        <Badge tone={CASE_KIND_TONE[item.id_kind] ?? 'slate'}>{item.canonical_id}</Badge>
        {item.severity ? <Badge tone={severityTone(item.severity)}>{item.severity}{item.cvss_score != null ? ` · ${item.cvss_score}` : ''}</Badge> : <Badge tone="amber">严重性待补</Badge>}
        {item.cwe_ids.slice(0, 3).map(cwe => <Badge key={cwe} tone="violet">{cwe}</Badge>)}
        {item.is_manual ? <Badge tone="violet">人工添加</Badge> : <Badge tone="sky">{item.source || '自动采集'}</Badge>}
        {item.status === 'pending_fetch' && <Badge tone="amber">待抓元数据</Badge>}
      </div>
      <h4>{item.title || item.canonical_id}</h4>
      <p>{item.summary || '暂无摘要。'}</p>
      <p className="small">
        {item.affected_products.length ? `影响 ${item.affected_products.slice(0, 3).join(' / ')}` : '受影响产品待补'}
        {item.fixed_versions.length ? ` · 已修 ${item.fixed_versions.slice(0, 2).join(', ')}` : ''}
        {item.published_at ? ` · 公开于 ${item.published_at.slice(0, 10)}` : ''}
      </p>
      {cves.length > 1 && <p className="small muted">关联 {cves.length} 个 CVE：{cves.slice(0, 5).join(', ')}{cves.length > 5 ? ' …' : ''}</p>}
    </div>
    <div className="case-card-side">
      <ContextDots item={item} />
      <b>{item.context_total ?? 0}</b>
      <span className="small muted">条上下文</span>
      {item.legacy_material_ids.length > 0 && <span className="small muted">素材 {item.legacy_material_ids.length}</span>}
      <button className="btn primary" onClick={event => { event.stopPropagation(); onOpen(); }}>查看上下文</button>
    </div>
  </article>;
}

/**
 * 人工添加。两条路径的差别是"这个洞有没有外部 id", 不是"谁填的":
 * 有 id → 登记成待抓元数据, 采集步去补; 没有 id(项目内部 bug) → 直接落地并标人工来源。
 */
function CaseAddForm() {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<'auto' | 'manual'>('auto');
  const [form, setForm] = useState({ canonical_id: '', title: '', summary: '', severity: '', source_url: '', cwe_ids: '', affected_products: '', references: '', code: '', note: '' });
  const submit = useMutation({
    mutationFn: () => addCase({
      mode,
      canonical_id: form.canonical_id.trim(),
      title: form.title.trim(),
      summary: form.summary.trim(),
      severity: form.severity.trim(),
      source_url: form.source_url.trim(),
      cwe_ids: splitList(form.cwe_ids),
      affected_products: splitList(form.affected_products),
      references: splitList(form.references),
      code: form.code,
      note: form.note.trim(),
    }),
    onSuccess: result => {
      void invalidateCase(qc);
      toast(result.created ? `已登记 ${result.canonical_id}` : `${result.canonical_id} 已存在，这次只补充了新信息`, 'success');
      setForm(f => ({ ...f, canonical_id: '', title: '', summary: '', code: '', note: '' }));
    },
    // 后端把"认不出这个 id"这类问题做成 400 + 中文 detail, 但 client 只抛出状态码 ——
    // 所以这里补一句人能看懂的话, 而不是把 "xxx: 400" 直接甩给用户。
    onError: error => toast(mode === 'auto' ? `添加失败(${error})：请确认 id 形如 CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q` : `添加失败(${error})：标题是必填项`, 'error'),
  });
  const canSubmit = mode === 'auto' ? Boolean(form.canonical_id.trim()) : Boolean(form.title.trim());
  return <section className="panel case-add">
    <div className="panel-head"><h3>添加漏洞案例</h3><span>知道 id 就贴 id（元数据自动抓），没有外部 id 的项目内部 bug 就完全手填</span><button className="btn" onClick={() => setOpen(value => !value)}>{open ? '收起' : '+ 添加'}</button></div>
    {open && <div className="panel-body">
      <div className="view-pills case-add-modes">
        <button className={`view-pill ${mode === 'auto' ? 'active' : ''}`} onClick={() => setMode('auto')}>按 ID 自动抓</button>
        <button className={`view-pill ${mode === 'manual' ? 'active' : ''}`} onClick={() => setMode('manual')}>完全手填</button>
      </div>
      {mode === 'auto'
        ? <p className="muted small">贴 CVE / GHSA / OSV id 即可。这里只登记，元数据（摘要、CVSS、CWE、影响版本、补丁）由采集步去抓 —— 抓不到也留着，回溯富化会再试。</p>
        : <p className="muted small">用于没有外部编号的洞（开源项目 issue / 内部 bug）。案例主键由标题 + 链接派生，同样的标题和链接再添一次还是同一条。</p>}
      <div className="filters">
        {mode === 'auto'
          ? <input className="search" placeholder="CVE-2021-44228 / GHSA-jfh8-c2jp-5v3q" value={form.canonical_id} onChange={event => setForm(f => ({ ...f, canonical_id: event.target.value }))} />
          : <input className="search" placeholder="标题（必填，如 xxx 组件 UAF）" value={form.title} onChange={event => setForm(f => ({ ...f, title: event.target.value }))} />}
        <input className="search" placeholder="严重性（如 high / 中危，可空）" value={form.severity} onChange={event => setForm(f => ({ ...f, severity: event.target.value }))} />
        <input className="search" placeholder="原文链接 / issue 链接" value={form.source_url} onChange={event => setForm(f => ({ ...f, source_url: event.target.value }))} />
      </div>
      <div className="filters">
        <input className="search" placeholder="CWE（逗号分隔，如 CWE-416, CWE-787）" value={form.cwe_ids} onChange={event => setForm(f => ({ ...f, cwe_ids: event.target.value }))} />
        <input className="search" placeholder="受影响产品（逗号分隔）" value={form.affected_products} onChange={event => setForm(f => ({ ...f, affected_products: event.target.value }))} />
        <input className="search" placeholder="外部引用（逗号分隔，多个链接）" value={form.references} onChange={event => setForm(f => ({ ...f, references: event.target.value }))} />
      </div>
      {mode === 'manual' && <input className="search" style={{ width: '100%', marginTop: 8 }} placeholder="摘要（影响什么、怎么触发）" value={form.summary} onChange={event => setForm(f => ({ ...f, summary: event.target.value }))} />}
      <textarea className="search" style={{ width: '100%', minHeight: 90, marginTop: 8, fontFamily: 'ui-monospace, monospace' }} placeholder="关键代码 / 说明（可空，会存成一条「人工补充」上下文）" value={form.code} onChange={event => setForm(f => ({ ...f, code: event.target.value }))} />
      <div className="split panel-actions"><button className="btn primary" disabled={!canSubmit || submit.isPending} onClick={() => submit.mutate()}>{submit.isPending ? '提交中…' : '登记案例'}</button><span className="muted small">重复添加不会插新行：同一条洞再添一次只是补充新信息。</span></div>
    </div>}
  </section>;
}

function Pagination({ page, pages, total, setOffset }: { page: number; pages: number; total: number; setOffset: (offset: number) => void }) {
  if (total === 0) return null;
  return <div className="pagination"><span className="muted">共 {total} 条 · 第 {page}/{pages} 页</span><button className="btn" disabled={page <= 1} onClick={() => setOffset((page - 2) * PAGE_SIZE)}>上一页</button><button className="btn" disabled={page >= pages} onClick={() => setOffset(page * PAGE_SIZE)}>下一页</button></div>;
}

/** 逗号 / 顿号 / 换行分隔的输入 → 去空去重的数组(用户从各处复制粘贴, 分隔符不会统一)。 */
function splitList(value: string): string[] {
  return Array.from(new Set(String(value).split(/[,，、\n]/).map(part => part.trim()).filter(Boolean)));
}
