import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Badge, EmptyState } from '../../components/ui';
import { useToast } from '../../components/Toast';
import {
  addProject, deleteProject, detectProjectPackages, fetchCases, fetchProjects,
  linkProjectCases, runProjectNativeSync, setProjectEnabled, updateProject,
} from '../../api/vulnerabilities';
import { openCaseDrawer, severityTone, type DrawerSetter } from './CaseDrawer';
import type { Project, ProjectPackage } from '../../types/vulnerability';

/** 自有源的展示名。采集步只实现了前两种,后两种在页面上如实标「未启用」。 */
const NATIVE_SOURCES: Array<{ id: string; label: string; hint: string }> = [
  { id: 'releases', label: '发布说明', hint: 'GitHub Releases(免 token)' },
  { id: 'changelog', label: 'CHANGELOG / SECURITY', hint: '仓库根目录的文本文件' },
  { id: 'github_advisories', label: 'GitHub 安全公告', hint: '需要 token，本期未启用' },
  { id: 'issues', label: 'Issues(security)', hint: '噪声大，本期只作线索' },
];
const NATIVE_LABEL = Object.fromEntries(NATIVE_SOURCES.map(item => [item.id, item.label]));
const SUPPORTED_NATIVE = new Set(['releases', 'changelog']);

function utcMinute(value: string | null | undefined): string {
  return value ? `${value.slice(0, 16).replace('T', ' ')} UTC` : '';
}

/**
 * 项目视图(P5a, 2026-10-19)。
 *
 * 为什么要有这一页: 案例库的主键是**洞**, 而领导要的「开源项目的 buglist」问的是
 * 「这个项目有哪些已知洞」。项目 = 一个仓 + 它的发布包; 案例关联**不新增任何采集**,
 * 只复用已有数据: OSV 写进案例的 `生态:包名`, 以及补丁上下文里的 `owner/repo`。
 * P5b(2026-10-20)加的是**独立的**自有源同步: 每晚 04:30 读项目自己的发布说明/CHANGELOG,
 * 只提取编号并逐个核实 —— 解析不到/核实不到都不建案例。
 *
 * 页面上必须说清三件事, 否则会误导:
 *   ① 0 条 ≠ 这个项目没有漏洞, 只表示"没有匹配到已收录的案例";
 *   ② 自动识别出来的包只是候选, 要人确认 —— monorepo 根 manifest 经常不是真正的发布包;
 *   ③ 自有源同步"无新增" ≠ 没漏洞, 公告里提到的编号也可能是第三方依赖的洞。
 */
export function ProjectsView({ setDrawer, onOpenMaterial }: { setDrawer: DrawerSetter; onOpenMaterial?: (itemId: number) => void }) {
  const qc = useQueryClient();
  const { toast } = useToast();
  const projects = useQuery({ queryKey: ['vulnerabilities', 'projects'], queryFn: () => fetchProjects(true) });
  const [selected, setSelected] = useState<number | null>(null);
  const items = projects.data?.items ?? [];
  const totalCases = items.reduce((sum, item) => sum + (item.case_total ?? 0), 0);

  const refresh = () => void qc.invalidateQueries({ queryKey: ['vulnerabilities', 'projects'] });
  const toggle = useMutation({
    mutationFn: ({ item, enabled }: { item: Project; enabled: boolean }) => setProjectEnabled(item.id, enabled),
    onSuccess: result => { toast(result.enabled ? `已启用：${result.display_name}` : `已停用：${result.display_name}`, 'success'); refresh(); },
    onError: error => toast(`操作失败(${error})`, 'error'),
  });
  const relink = useMutation({
    mutationFn: (id: number) => linkProjectCases(id),
    onSuccess: result => { toast(`重扫完成：匹配 ${result.cases_matched} 条案例，新增 ${result.links_created} 条关联`, 'success'); refresh(); void qc.invalidateQueries({ queryKey: ['vulnerabilities', 'project-cases'] }); },
    onError: error => toast(`重扫失败(${error})`, 'error'),
  });
  const syncNative = useMutation({
    mutationFn: (id: number) => runProjectNativeSync(id),
    // 不谎称"已完成":这是后台跑批,主链路占锁时还会排队重试。用户按 F5/等一分钟再看。
    onSuccess: () => toast('已提交后台同步(逐条核实编号,完成后刷新本页查看结果)', 'success'),
    onError: error => toast(`提交同步失败(${error})`, 'error'),
  });
  const remove = useMutation({
    mutationFn: (id: number) => deleteProject(id),
    onSuccess: () => { toast('已删除项目（案例本身不受影响）', 'success'); setSelected(null); refresh(); },
    onError: error => toast(`删除失败(${error})`, 'error'),
  });
  const askRemove = async (item: Project) => {
    const ok = await confirm(`确认删除项目「${item.display_name}」?\n只删项目与它的关联，案例库里的洞本身不受影响。`);
    if (ok) remove.mutate(item.id);
  };

  return <div className="v11-view">
    <div className="metric-grid">
      {([
        ['项目数', items.length, '资产相关 + 研究标杆，上限建议 ≤100', 'sky'],
        ['关联案例', totalCases, '按包名或仓库匹配到的洞（同一案例只计一次）', 'violet'],
        ['启用中', items.filter(item => item.enabled).length, '停用的项目不参与每晚关联', 'green'],
      ] as Array<[string, number, string, 'sky' | 'violet' | 'green']>).map(([label, value, hint, tone]) =>
        <div className={`insight-metric metric-bg-${tone}`} key={label}><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-hint">{hint}</div></div>)}
    </div>

    <section className="panel case-add">
      <div className="panel-head"><h3>收录范围</h3><span>案例关联复用已有数据；项目自有源每日 04:30 单独同步</span></div>
      <div className="panel-body">
        <p className="muted small">
          项目与案例的关联只有两种证据：① 案例的<b>受影响产品</b>与项目的发布包写成完全相同的「生态:包名」；
          ② 案例的<b>补丁仓库 / 引用链接</b>指向这个仓。因此<b>0 条不等于这个项目没有漏洞</b>，
          只表示「没有匹配到已收录的案例」—— 没有被 NVD/OSV 收录、或还没有补丁的洞不会出现在这里。
          自动识别出的包只是候选，请确认后再保存（monorepo 的根 manifest 经常不是真正的发布包）。
        </p>
        <p className="muted small" style={{ marginTop: 8 }}>
          <b>自有源</b>指项目自己在<b>发布说明</b>或 <b>CHANGELOG/SECURITY</b> 文件里写出来的安全修复。
          系统只从这些文本里提取 <b>CVE / GHSA 编号</b>，逐个到 NVD/OSV 核实：
          核实得到的才建案例并以「项目公告」关联（置信度 0.6）；核实不到的只记为线索，<b>不会出现在案例库</b>。
          因此公告里提到某个编号，说明的是「项目公告里提到」，不等于该项目的漏洞 ——
          它也可能是第三方依赖的洞。没配置自有源、或最近没有新公告，只表示<b>没抓到东西</b>，
          同样不等于「这个项目没有漏洞」。
        </p>
      </div>
    </section>

    <ProjectAddForm onAdded={refresh} />

    <section className="panel">
      <div className="panel-head"><h3>项目清单</h3><span>建议 Tier 1（我司资产相关）≤50、Tier 2（研究标杆）≤50</span></div>
      <div className="panel-body">
        {projects.isLoading
          ? <p className="muted small">加载中…</p>
          : items.length
            ? <div className="case-list">{items.map(item => <ProjectCard
              key={item.id} item={item} expanded={selected === item.id}
              onToggle={() => setSelected(selected === item.id ? null : item.id)}
              onRelink={() => relink.mutate(item.id)}
              onSync={() => syncNative.mutate(item.id)}
              onToggleEnabled={() => toggle.mutate({ item, enabled: !item.enabled })}
              onRemove={() => void askRemove(item)}
              onOpenMaterial={onOpenMaterial} setDrawer={setDrawer}
            />)}</div>
            : <EmptyState title="还没有项目" description="先用「+ 添加项目」加入 10 个标杆项目（如 apache/logging-log4j2、django/django、curl/curl），关联会立即跑一次。" />}
      </div>
    </section>
  </div>;
}

function ProjectCard({ item, expanded, onToggle, onRelink, onSync, onToggleEnabled, onRemove, setDrawer, onOpenMaterial }: {
  item: Project;
  expanded: boolean;
  onToggle: () => void;
  onRelink: () => void;
  onSync: () => void;
  onToggleEnabled: () => void;
  onRemove: () => void;
  setDrawer: DrawerSetter;
  onOpenMaterial?: (itemId: number) => void;
}) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [packagesText, setPackagesText] = useState('');
  const [sources, setSources] = useState<string[]>(item.native_sources ?? []);
  const saveSettings = useMutation({
    // 改包映射会改变"哪些洞算这个项目的" —— 后端 PATCH 后立刻全量重扫, 所以这里等它跑完。
    mutationFn: () => updateProject(item.id, { packages: splitLines(packagesText), native_sources: sources }),
    onSuccess: result => {
      toast(`已保存：匹配 ${result.link?.cases_matched ?? 0} 条案例`, 'success');
      setEditing(false);
      void qc.invalidateQueries({ queryKey: ['vulnerabilities', 'projects'] });
      void qc.invalidateQueries({ queryKey: ['vulnerabilities', 'project-cases', item.id] });
    },
    onError: error => toast(`保存失败(${error})：包名格式为「生态:包名」，如 PyPI:django`, 'error'),
  });
  const lastRun = item.sync_cursor?.last_run;
  const severity = Object.entries(item.by_severity ?? {}).sort((a, b) => b[1] - a[1]);
  return <article className="case-card">
    <div className="case-card-main">
      <div className="badges">
        <Badge tone={item.tier === 'asset' ? 'red' : 'sky'}>{item.tier === 'asset' ? '资产相关' : '研究标杆'}</Badge>
        <Badge tone="slate">{item.platform}</Badge>
        {!item.enabled && <Badge tone="amber">已停用</Badge>}
        {severity.map(([name, count]) => <Badge key={name} tone={severityTone(name)}>{name} {count}</Badge>)}
      </div>
      <h4 style={item.enabled ? undefined : { opacity: 0.6 }}>{item.display_name}</h4>
      <p className="small">{item.url}</p>
      <p className="small">
        {item.packages.length
          ? `发布包：${item.packages.map(pkg => `${pkg.ecosystem}:${pkg.name}`).join(' / ')}`
          : '发布包：未配置（只能按仓库关联）'}
      </p>
      <p className="small">
        {item.native_sources.length
          ? `自有源：${item.native_sources.map(id => NATIVE_LABEL[id] ?? id).join(' / ')}`
          : '自有源：未配置（不抓项目公告）'}
        {item.last_synced_at ? ` · 上次同步 ${utcMinute(item.last_synced_at)}` : ''}
      </p>
      {lastRun && <p className="small muted">
        上次运行：新公告 {lastRun.releases_new ?? 0} 条、文件变更 {lastRun.files_changed ?? 0} 个；
        编号 核实 {lastRun.created ?? 0} 建案 / 已有 {lastRun.existing ?? 0} / 未核实 {lastRun.unverified ?? 0}
        {lastRun.errors ? `；错误 ${lastRun.errors}` : ''}
        {lastRun.notes?.length ? <><br />{lastRun.notes.join('；')}</> : null}
      </p>}
    </div>
    <div className="case-card-side">
      <b>{item.case_total}</b>
      <span className="small muted">条关联案例</span>
      <button className="btn primary" onClick={onToggle}>{expanded ? '收起案例' : '看案例'}</button>
      <div className="split" style={{ gap: 6, marginTop: 6 }}>
        <button className="btn sm" onClick={onRelink}>重扫关联</button>
        <button className="btn sm" onClick={onSync}>同步自有源</button>
        <button className="btn sm" onClick={() => { setPackagesText(item.packages.map(pkg => `${pkg.ecosystem}:${pkg.name}`).join('\n')); setSources(item.native_sources); setEditing(value => !value); }}>编辑配置</button>
        <button className="btn sm" onClick={onToggleEnabled}>{item.enabled ? '停用' : '启用'}</button>
        <button className="btn sm" onClick={onRemove}>删除</button>
      </div>
    </div>
    {editing && <div style={{ width: '100%', marginTop: 8 }}>
      <textarea
        className="search"
        style={{ width: '100%', minHeight: 64, fontFamily: 'ui-monospace, monospace' }}
        placeholder={'每行一个：PyPI:django'}
        value={packagesText}
        onChange={event => setPackagesText(event.target.value)}
      />
      <div className="filters" style={{ marginTop: 8 }}>
        {NATIVE_SOURCES.map(source => <label key={source.id} className="small" title={source.hint}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 4, opacity: SUPPORTED_NATIVE.has(source.id) ? 1 : 0.55 }}>
          <input
            type="checkbox"
            checked={sources.includes(source.id)}
            disabled={!SUPPORTED_NATIVE.has(source.id)}
            onChange={event => setSources(prev => event.target.checked
              ? [...prev.filter(id => id !== source.id), source.id]
              : prev.filter(id => id !== source.id))}
          />
          {source.label}
        </label>)}
      </div>
      <p className="muted small">发布说明与 CHANGELOG 免 token；GitHub 安全公告与 Issues 本期未启用（灰掉的勾选不会生效）。</p>
      <div className="split panel-actions">
        <button className="btn primary sm" disabled={saveSettings.isPending} onClick={() => saveSettings.mutate()}>{saveSettings.isPending ? '保存并重扫…' : '保存并重扫'}</button>
        <span className="muted small">清空发布包并保存 = 该项目只按仓库关联；自有源全不勾 = 不抓项目公告。</span>
      </div>
    </div>}
    {expanded && <ProjectCases projectId={item.id} setDrawer={setDrawer} onOpenMaterial={onOpenMaterial} />}
  </article>;
}

/** 项目详情 = 案例时间线。只展示最近 50 条（按公开时间倒序，与案例库同一排序口径）。 */
function ProjectCases({ projectId, setDrawer, onOpenMaterial }: { projectId: number; setDrawer: DrawerSetter; onOpenMaterial?: (itemId: number) => void }) {
  const cases = useQuery({
    queryKey: ['vulnerabilities', 'project-cases', projectId],
    queryFn: () => fetchCases({ project_id: projectId, limit: 50 }),
  });
  const items = cases.data?.items ?? [];
  const total = cases.data?.total ?? 0;
  if (cases.isLoading) return <p className="muted small" style={{ width: '100%', marginTop: 8 }}>加载项目案例…</p>;
  if (!items.length) {
    return <p className="muted small" style={{ width: '100%', marginTop: 8 }}>
      没有匹配到已收录的案例。这不代表项目没有漏洞：只有被 NVD/OSV 收录过的洞才在案例库里，
      而且关联要求包名完全一致或补丁链接指向这个仓。可以先补全发布包再「重扫关联」。
    </p>;
  }
  return <div className="timeline" style={{ width: '100%', marginTop: 10 }}>
    {items.map(item => <div className="timeline-item clickable" key={item.id} onClick={() => openCaseDrawer(item, setDrawer, onOpenMaterial)}>
      <div className="row-title">
        <span><Badge tone="red">{item.canonical_id}</Badge><b style={{ marginLeft: 6 }}>{item.title || item.canonical_id}</b></span>
        <span className="muted small">{item.severity || '严重性待补'}{item.published_at ? ` · 公开于 ${item.published_at.slice(0, 10)}` : ''}</span>
      </div>
    </div>)}
    {total > items.length && <p className="muted small">共 {total} 条，这里显示最近 {items.length} 条；完整列表可在「漏洞事件库」按项目筛选。</p>}
  </div>;
}

/**
 * 添加项目。**自动识别是显式动作**: 建项目本身不联网(隧道上每个请求都有固定开销),
 * 识别结果填进输入框由人确认 —— 不直接落库。
 */
function ProjectAddForm({ onAdded }: { onAdded: () => void }) {
  const { toast } = useToast();
  const [open, setOpen] = useState(false);
  const [url, setUrl] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [tier, setTier] = useState<'benchmark' | 'asset'>('benchmark');
  const [packagesText, setPackagesText] = useState('');
  // 新项目默认盯发布说明 + CHANGELOG(都免 token);不勾 = 明确不抓公告。
  const [sources, setSources] = useState<string[]>(['releases', 'changelog']);
  const [notes, setNotes] = useState<string[]>([]);

  const detect = useMutation({
    mutationFn: () => detectProjectPackages(url.trim()),
    onSuccess: result => {
      setNotes(result.notes ?? []);
      if (!result.packages.length) {
        toast('没有从根目录 manifest 识别出发布包，可以手动填「生态:包名」', 'error');
        return;
      }
      // 同一个生态只收第一个候选(与后端解析口径一致), 其余作为提示保留
      const seen = new Set<string>();
      const picked: ProjectPackage[] = [];
      for (const pkg of result.packages) {
        if (seen.has(pkg.ecosystem)) continue;
        seen.add(pkg.ecosystem);
        picked.push({ ecosystem: pkg.ecosystem, name: pkg.name });
      }
      setPackagesText(picked.map(pkg => `${pkg.ecosystem}:${pkg.name}`).join('\n'));
      toast(`识别到 ${picked.length} 个候选包（来自 ${result.fetched.join(', ') || 'manifest'}），确认后保存`, 'success');
    },
    onError: error => toast(`识别失败(${error})：检查仓地址是否可访问`, 'error'),
  });
  const submit = useMutation({
    mutationFn: () => addProject({
      url: url.trim(),
      display_name: displayName.trim(),
      tier,
      packages: splitLines(packagesText),
      native_sources: sources,
    }),
    onSuccess: result => {
      toast(result.created
        ? `已添加 ${result.project.display_name}：匹配 ${result.link.cases_matched} 条案例`
        : `项目已存在，已合并发布包：匹配 ${result.link.cases_matched} 条案例`, 'success');
      setUrl(''); setDisplayName(''); setPackagesText(''); setNotes([]); setSources(['releases', 'changelog']);
      onAdded();
    },
    onError: error => toast(`添加失败(${error})：仓地址支持 github:org/repo 或 https://github.com/org/repo`, 'error'),
  });

  return <section className="panel case-add">
    <div className="panel-head">
      <h3>添加项目</h3>
      <span>一个开源项目 = 一个仓 + 它的发布包；添加后立即按包名/仓库回填已有案例</span>
      <button className="btn" onClick={() => setOpen(value => !value)}>{open ? '收起' : '+ 添加项目'}</button>
    </div>
    {open && <div className="panel-body">
      <div className="filters">
        <input className="search" placeholder="github:apache/logging-log4j2 / https://github.com/django/django" value={url} onChange={event => setUrl(event.target.value)} />
        <input className="search" placeholder="显示名（可空，默认用仓名）" value={displayName} onChange={event => setDisplayName(event.target.value)} />
        <select value={tier} onChange={event => setTier(event.target.value as 'benchmark' | 'asset')}>
          <option value="benchmark">研究标杆</option>
          <option value="asset">资产相关</option>
        </select>
        <button className="btn" disabled={!url.trim() || detect.isPending} onClick={() => detect.mutate()}>{detect.isPending ? '识别中…' : '自动识别发布包'}</button>
      </div>
      <textarea
        className="search"
        style={{ width: '100%', minHeight: 70, marginTop: 8, fontFamily: 'ui-monospace, monospace' }}
        placeholder={'发布包，每行一个（可空）\nPyPI:django\nnpm:lodash\nMaven:org.apache.logging.log4j:log4j-core'}
        value={packagesText}
        onChange={event => setPackagesText(event.target.value)}
      />
      <div className="filters" style={{ marginTop: 8 }}>
        <span className="muted small">自有安全源：</span>
        {NATIVE_SOURCES.map(source => <label key={source.id} className="small" title={source.hint}
          style={{ display: 'inline-flex', alignItems: 'center', gap: 4, opacity: SUPPORTED_NATIVE.has(source.id) ? 1 : 0.55 }}>
          <input
            type="checkbox"
            checked={sources.includes(source.id)}
            disabled={!SUPPORTED_NATIVE.has(source.id)}
            onChange={event => setSources(prev => event.target.checked
              ? [...prev.filter(id => id !== source.id), source.id]
              : prev.filter(id => id !== source.id))}
          />
          {source.label}
        </label>)}
      </div>
      {notes.length > 0 && <p className="muted small">识别提示：{notes.join('；')}</p>}
      <div className="split panel-actions">
        <button className="btn primary" disabled={!url.trim() || submit.isPending} onClick={() => submit.mutate()}>{submit.isPending ? '提交中…' : '添加并关联'}</button>
        <span className="muted small">没有发布包的纯 C/C++ 项目可以留空，只按仓库关联。</span>
      </div>
    </div>}
  </section>;
}

/** 每行一个包；也接受逗号/顿号分隔（用户从各处复制粘贴）。 */
function splitLines(value: string): string[] {
  return Array.from(new Set(String(value).split(/[\n,，、]/).map(part => part.trim()).filter(Boolean)));
}
