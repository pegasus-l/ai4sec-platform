import { useMemo, useState, useEffect, useRef, useCallback } from 'react';
import { ThemeToggle } from '../../components/ThemeToggle';
import { Star, ListChecks, Settings, ArrowUpRight, Activity, ShieldCheck, RefreshCw, type LucideIcon } from 'lucide-react';
import { keepPreviousData, useQuery, useQueryClient } from '@tanstack/react-query';
import { Badge, MetricCard, EmptyState } from '../../components/ui';
import { ConfirmModal, type ConfirmRequest } from '../../components/ConfirmModal';
import { useToast } from '../../components/Toast';
import { useDrawerStack } from '../../components/DrawerStack';
import {
  fetchToday, fetchLibraryPage, fetchLibraryStats, fetchReproRuns, fetchConversions, fetchClassifyStats,
  fetchDetail, fetchReproTask, fetchReproFullLog, startRepro, stopRepro, cleanupRepro, markConversion,
  streamReproLogs, classifyLogLine, stripAnsi,
} from './capabilityQueries';
import type { CapabilityItem, ReproTask, ConversionRecord, CapabilityView, LibraryStats, LibraryFormKey, ReproBucketKey } from './capabilityTypes';
import { CapabilityOps, CapabilityOpsQuality, CapabilityOpsRuns } from './CapabilityOps';

const navGroups: Array<{ title: string; items: Array<{ id: CapabilityView; icon: LucideIcon; title: string }> }> = [
  { title: '能力洞察', items: [
    { id: 'today', icon: Star, title: '今日能力' },
    { id: 'library', icon: ListChecks, title: '能力库' },
    { id: 'repro', icon: Settings, title: '复现验证' },
    { id: 'conversion', icon: ArrowUpRight, title: '能力转化' },
  ]},
  { title: '运营', items: [
    { id: 'ops-overview', icon: Activity, title: '运营概览' },
    { id: 'ops-quality', icon: ShieldCheck, title: '质量审计' },
    { id: 'ops-runs', icon: RefreshCw, title: 'Pipeline 运行' },
  ]},
];

const conversionGroups = ['待评估', '待复现', '复现中', '复现成功', '待集成', '持续观察', '已采用'];

interface ConvertFormData { status: string; scenario: string; owner: string; next_action: string; notes: string; }

/** 多选 chip 切换(同 NewsPage): 已选则移除, 未选则追加 */
function toggleValue(values: string[], value: string): string[] {
  return values.includes(value) ? values.filter(v => v !== value) : [...values, value];
}

/** 是否具备可跳转的复现结果(success/partial/failed/in_progress 状态, 或 payload 里有 repro_result) */
function hasReproResult(p: CapabilityItem['payload'] | undefined): boolean {
  const s = p?.repro_status;
  return ['success', 'succeeded', 'partial', 'failed', 'error', 'in_progress'].includes(s ?? '') || Boolean(p?.repro_result);
}

/** 复现状态徽标文案/色调(含 not_supported=无需复现)。
 *  2026-10-29 更名: 原「无法复现」。它同时覆盖两种互不相干的情形 —— 项目根本不是 Web(复现维度不适用)、
 *  依赖 Docker 等本环境没有的条件(跑了也只会 FAILURE)。两者都是「平台决定不跑/跑了没有意义」，
 *  共同点是**不该被读成「这个项目复现不出来」**。色调从 red 改 slate: 它不是失败。
 *
 *  2026-10-31 按用户要求把两种成因在页面上分开, 文案读 repro_skip_reason:
 *  `non_web` → 「非 Web(不参与复现)」(项目根本没有浏览器界面, 复现维度不适用);
 *  `env_unsupported`(或缺字段的旧数据)→ 仍写「无需复现」(是 Web, 但本环境缺 Docker/KVM)。
 *  10-29 那版故意统一措辞是为了不让卡片上两种说法打架; 现在看, 打架的是「不是 Web」与
 *  「跑不起来」这两件事挤在一个词里 —— 分开才不误导。 */
const REPRO_LABEL: Record<string, string> = {
  candidate: '可复现', in_progress: '复现中', no_code: '无代码', success: '已复现',
  succeeded: '已复现', partial: '部分复现', failed: '复现失败', error: '复现异常',
  not_supported: '无需复现', demo_verified: '官方Demo',
};
/** 「无需复现」终态的两种成因 → 展示文案。缺 repro_skip_reason 的旧数据按 Docker 口径兜底,
 *  与抽屉「复现说明」的兜底一致(那里也是 non_web 以外一律当环境边界)。 */
const reproNotSupportedLabel = (skipReason?: string): string =>
  skipReason === 'non_web' ? '非 Web(不参与复现)' : '无需复现';
const reproBadgeLabel = (rs?: string, skipReason?: string) =>
  rs === 'not_supported' ? reproNotSupportedLabel(skipReason) : REPRO_LABEL[rs ?? ''] ?? rs ?? '未知';
const reproBadgeTone = (rs?: string): 'green' | 'sky' | 'slate' | 'amber' | 'red' =>
  rs === 'candidate' ? 'green' : rs === 'in_progress' ? 'sky' : rs === 'no_code' ? 'slate' : rs === 'not_supported' ? 'slate' : 'amber';

/** 前端口径: 只要 payload 标了 is_web=false 就不算"可复现", LOWCONF 也算非 web。
 *  与后端 is_non_web_blocked 有意不同 —— 后端给 LOWCONF 留了例外(LLM 判 web 但无佐证,
 *  放它入队走 CLI 复现、由复现报告回写 is_web 自我纠正), 但那是**队列**口径, 不该让界面
 *  继续对外宣称"可复现"。实测 LOWCONF 有 103 条, 用户在页面上看到的就是它们。 */
const isNonWebBlocked = (p: CapabilityItem['payload'] | undefined): boolean => p?.is_web === false;
/** 是否渲染"可复现"徽标: 非 web 且仍是 candidate(待复现) 时不渲染 —— 同排已有「非Web」徽标承载
 *  该信息, 直接省略以免两个"非Web"并排。其余状态(无需复现/复现失败等)仍有信息量, 照常显示。 */
const showReproBadge = (p: CapabilityItem['payload'] | undefined): boolean =>
  !(isNonWebBlocked(p) && p?.repro_status === 'candidate');


function matchItem(item: CapabilityItem, q: string): boolean {
  const p = item.payload ?? {};
  const hay = [
    item.title, item.summary ?? '', item.source_url ?? '',
    p.display_title, p.display_work_name, p.display_topic, p.one_liner, p.overview,
    p.summary, p.code_url,
    Array.isArray(p.tech_points) ? p.tech_points.join(' ') : '',
  ].filter(Boolean).join(' ').toLowerCase();
  return hay.includes(q.toLowerCase());
}

export function CapabilityPage() {
  const [view, setView] = useState<CapabilityView>('today');
  const [search, setSearch] = useState('');
  // 【跳转复现】从能力库点「查看复现」时记录目标能力, 切到复现验证页后由 CapabilityRepro 选中对应任务
  const [reproTargetItemId, setReproTargetItemId] = useState<number | null>(null);
  const { push, clear } = useDrawerStack();
  const { toast } = useToast();
  const qc = useQueryClient();

  const { data: todayData, isLoading: todayLoading } = useQuery({ queryKey: ['cap-today'], queryFn: fetchToday, staleTime: 300_000 });
  const { data: libraryStatsData } = useQuery({ queryKey: ['cap-library-stats'], queryFn: fetchLibraryStats, staleTime: 300_000 });
  const { data: reproData } = useQuery({ queryKey: ['cap-repro'], queryFn: fetchReproRuns, staleTime: 1_000, refetchInterval: 5_000 });
  const { data: convData } = useQuery({ queryKey: ['cap-conversions'], queryFn: fetchConversions, staleTime: 300_000 });
  const { data: statsData } = useQuery({ queryKey: ['cap-classify-stats'], queryFn: fetchClassifyStats, staleTime: 300_000 });

  const todayItems = ((todayData as Record<string, unknown> | undefined)?.items ?? []) as CapabilityItem[];
  const reproRuns = ((reproData as Record<string, unknown> | undefined)?.items ?? []) as ReproTask[];
  const conversions = ((convData as Record<string, unknown> | undefined)?.items ?? []) as ConversionRecord[];
  const stats = statsData ?? { total: 0, classified: 0, unclassified: 0, web_count: 0 };
  const libraryStats = libraryStatsData as LibraryStats | undefined;

  // 【搜索】搜索框全局过滤: 今日能力 + 能力库(跨标题/仓库/技术点/概述), 空则显示全部
  const trimmedSearch = search.trim();
  const filteredToday = useMemo(
    () => (trimmedSearch ? todayItems.filter(i => matchItem(i, trimmedSearch)) : todayItems),
    [todayItems, trimmedSearch],
  );

  const viewRef = useRef<HTMLDivElement>(null);
  useEffect(() => { if (viewRef.current) viewRef.current.scrollTop = 0; }, [view]);

  // 【改动 4】抽屉打开时调 fetchDetail 获取完整 payload
  // 【跳转复现】从能力库/详情抽屉跳到复现验证页, 自动选中该能力的复现任务
  const openReproView = useCallback((item: CapabilityItem) => {
    setReproTargetItemId(item.id);
    setView('repro');
  }, []);

  const openDetail = useCallback((item: CapabilityItem) => {
    push({
      title: item.payload?.display_title || item.title,
      subtitle: `${item.payload?.source_type ?? ''} · score ${item.score}`,
      render: () => <CapabilityDetailContent itemId={item.id} initialItem={item} onViewRepro={() => { clear(); openReproView(item); }} onRepro={async () => {
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
  }, [push, clear, toast, qc, openReproView]);

  const openConversion = useCallback((conv: ConversionRecord) => {
    push({
      title: conv.title,
      subtitle: `转化状态: ${conv.status} · 负责人: ${conv.owner || '未分配'}`,
      render: () => <ConversionDetailContent conv={conv} />,
    });
  }, [push]);

  return <main className="main">
    <aside className="ai4sec-sidebar">
      <a href="/" style={{ display: "block", padding: "8px 12px", color: "var(--accent)", fontSize: 12, textDecoration: "none", borderBottom: "1px solid var(--line)" }}>&larr; 返回</a>
      <div className="ai4sec-sidebar-head"><div className="label"><span className="dot" /><span>能力洞察</span></div><h2>前沿项目能力化</h2><p>从资讯筛选可复现项目，到自动复现验证，再到能力转化落地。</p></div>
      <nav className="nav-scroll">{navGroups.map(group => <div className="nav-group" key={group.title}><div className="group-title">{group.title}</div>{group.items.map(item => { const Icon = item.icon; return <button key={item.id} className={`nav-item ${view === item.id ? 'active' : ''}`} onClick={() => setView(item.id)}><Icon size={18} /><span>{item.title}</span>{item.id === 'today' && todayItems.length > 0 && <span className="badge badge-green">{todayItems.length}</span>}{item.id === 'library' && (libraryStats?.total ?? 0) > 0 && <span className="badge badge-sky">{libraryStats?.total}</span>}{item.id === 'repro' && reproRuns.length > 0 && <span className="badge badge-amber">{reproRuns.length}</span>}{item.id === 'conversion' && conversions.length > 0 && <span className="badge badge-violet">{conversions.length}</span>}</button>; })}</div>)}</nav>
      <div className="ai4sec-sidebar-note">能力洞察不重复资讯流，而是把前沿论文和开源项目推进到评分、复现和能力转化。能力详情从今日能力、能力库、复现验证或能力转化点击进入。</div>
    <div className="ai4sec-sidebar-footer" style={{ marginTop: "auto", padding: "8px 12px", borderTop: "1px solid var(--line)", display: "flex", alignItems: "center" }}><ThemeToggle /></div>
    </aside>
    <section className="content">
      <section className="content-head">
        <div className="content-title"><span className="label">{navGroups.flatMap(g => g.items).find(i => i.id === view)?.title ?? '能力洞察'}</span><h1>{heroTitle(view)}</h1><p>{heroCopy(view)}</p></div>
        <div className="head-actions"><label className="search"><span>⌕</span><input placeholder="搜索能力 / 仓库 / 技术点" value={search} onChange={e => setSearch(e.target.value)} /></label><button className="btn" onClick={async () => { await qc.invalidateQueries({ predicate: q => typeof q.queryKey[0] === 'string' && (q.queryKey[0] as string).startsWith('cap-') }); toast('数据已刷新', 'success'); }}>刷新数据</button></div>
      </section>
      <div className="content-body view" ref={viewRef}>
        {todayLoading && view === 'today' && <EmptyState title="正在加载" description="从 /api/capabilities/today 拉取数据。" />}
        {view === 'today' && <CapabilityToday items={filteredToday} stats={stats} openDetail={openDetail} />}
        {view === 'library' && <CapabilityLibrary stats={libraryStats} search={search} openDetail={openDetail} onViewRepro={openReproView} />}
        {view === 'repro' && <CapabilityRepro runs={reproRuns} openDetail={openDetail} targetItemId={reproTargetItemId} onTargetConsumed={() => setReproTargetItemId(null)} />}
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
    if (viewMode === '高可复现') return items.filter(i => (i.payload?.repro_status === 'candidate' || i.payload?.code_url) && i.payload?.repro_status !== 'not_supported' && !isNonWebBlocked(i.payload));
    if (viewMode === '高应用潜力') return items.filter(i => (i.payload?.application_scenarios ?? []).length > 0);
    if (viewMode === '需人工判断') return items.filter(i => i.payload?.repro_status === 'no_code' || !i.payload?.code_url);
    return items;
  }, [items, viewMode]);

  return <div className="grid">
    <div className="grid cols-4">
      <MetricCard label="今日能力" value={items.length} hint="最近 24 小时新增" tone="green" />
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

function CapabilityCard({ item, rank, onClick, onViewRepro }: { item: CapabilityItem; rank: number; onClick: () => void; onRepro: () => void; onViewRepro?: (item: CapabilityItem) => void }) {
  const p = item.payload ?? {};
  const sourceType = p.source_type || (item.source_url?.includes('github.com') ? 'github' : 'arxiv');
  const reproTag = p.repro_status === 'candidate' ? 'green' : p.repro_status === 'in_progress' ? 'sky' : p.repro_status === 'no_code' ? 'slate' : p.repro_status === 'not_supported' ? 'slate' : 'amber';
  const reproText = reproBadgeLabel(p.repro_status, p.repro_skip_reason);
  return <div className="asis-card clickable" onClick={onClick}>
    <div className="rank">{rank}</div>
    <div>
      <h4>{p.display_title || p.display_theme || p.one_liner || item.title}</h4>
      <p>{p.overview || p.one_liner || item.summary}</p>
      <div className="badges">
        <Badge tone={sourceType === 'github' ? 'sky' : 'violet'}>{sourceType}</Badge>
        {p.capability_type && <Badge tone="green">{p.capability_type}</Badge>}
        {showReproBadge(p) && <Badge tone={reproTag as 'green' | 'sky' | 'slate' | 'amber' | 'red'}>{reproText}</Badge>}
        {p.is_web ? <Badge tone="amber">Web{p.web_framework ? `:${p.web_framework}` : ''}</Badge> : <Badge tone="slate">非Web</Badge>}
        {p.demo_url && <Badge tone="green">官方 Demo</Badge>}
      </div>
      {onViewRepro && hasReproResult(p) && <button className="btn" style={{ marginTop: 6, padding: '2px 8px', fontSize: 11 }} onClick={(e) => { e.stopPropagation(); onViewRepro(item); }}>查看复现 →</button>}
    </div>
    <div style={{ display: 'grid', gap: 6, justifyItems: 'end' }}>
      <div className="score-ring" title="能力综合评分（1–5）">{item.score}</div>
    </div>
  </div>;
}

// ========== 能力库（改动 1: 4 个视图 + 改动 3: classifyBatch 按钮）==========
// 复现芯片名 → 后端 repro 键(与 /items/stats 的 repro 桶同名)
const REPRO_CHIP_KEY: Record<string, ReproBucketKey> = {
  '官方 Demo': 'demo', '完整复现': 'success', '部分复现': 'partial', '复现中': 'in_progress',
  '待复现': 'pending', '复现失败': 'failed', '无需复现': 'not_supported',
};
// 桶 → 工程可用性视图的分组标题; 顺序即展示顺序
const ENGINEERING_BUCKET_LABEL: Record<string, string> = {
  demo: '官方 Demo', success: '完整复现', partial: '部分复现', in_progress: '复现中',
  pending: '待 Web 复现', failed: '复现失败', not_supported: '无需复现', non_web: '非 Web(不参与复现)',
};
const ENGINEERING_BUCKET_ORDER = ['demo', 'success', 'partial', 'in_progress', 'pending', 'failed', 'not_supported', 'non_web'] as const;

/** 单条能力卡落在哪个「可体验·复现」桶, 判据与后端 REPRO_PREDICATES 一致:
 *  官方 Demo 是独立维度(有 demo_url 即归它, 不论 is_web); 「无需复现」是终态但有两种成因,
 *  按 repro_skip_reason 分开(2026-10-31): 分类阶段判死「不是 Web」→ 归「非 Web」组;
 *  是 Web 但环境缺 Docker/KVM → 留「无需复现」组。芯片 not_supported 数的是后端谓词,
 *  与后者同源, 所以分组与芯片对得上; 其余非 web 归「非 Web」;
 *  剩下的按 repro_status 落桶(缺失 / candidate / no_code → 待复现)。
 *  前端此前另有一份自己的判据, 且漏了 'succeeded'(分组显示 1 而芯片显示 2) —— 统一到这一处。 */
function reproBucketOf(p: CapabilityItem['payload'] | undefined): string | null {
  const rs = p?.repro_status;
  if (p?.demo_url) return 'demo';
  if (rs === 'not_supported') return p?.repro_skip_reason === 'non_web' ? 'non_web' : 'not_supported';
  if (!p?.is_web) return 'non_web';
  if (rs === 'success' || rs === 'succeeded') return 'success';
  if (rs === 'partial') return 'partial';
  if (rs === 'in_progress') return 'in_progress';
  if (rs === 'failed' || rs === 'error') return 'failed';
  return 'pending';
}

function CapabilityLibrary({ stats, search, openDetail, onViewRepro }: { stats?: LibraryStats; search: string; openDetail: (item: CapabilityItem) => void; onViewRepro: (item: CapabilityItem) => void }) {
  const qc = useQueryClient();   // 【预取下一页】
  const [viewMode, setViewMode] = useState<'列表视图' | '能力分类' | '应用场景' | '工程可用性'>('列表视图');
  // 【正交双维度多选筛选】形态(Web/非Web) × 可体验·复现(官方Demo/完整复现/…)。
  // 计数全部来自 /items/stats 服务端全量聚合(不受 fetch 窗口/搜索影响)。
  // 形态默认只选 Web(保持旧默认"隐藏非 Web 噪音");
  // 可体验默认选「待复现」(2026-10-31 用户要求: 进页面先看"该复现的"), 再点一次该芯片即取消。
  const [formChips, setFormChips] = useState<string[]>(['Web']);
  const [reproChips, setReproChips] = useState<string[]>(['待复现']);
  const [page, setPage] = useState(1);
  // 只看非 Web 时, 复现维度整个不适用(非 web 已被 web 把关挡在复现队列外) —— 那排 chip 整排失效,
  // 若还留着已选的复现条件会把列表筛成空, 所以一并清掉。
  const onlyNonWeb = formChips.includes('非Web') && !formChips.includes('Web');
  useEffect(() => { if (onlyNonWeb) setReproChips([]); }, [onlyNonWeb]);
  const chipCount = (chip: string): number | undefined => {
    if (!stats) return undefined;
    switch (chip) {
      case 'Web': return stats.web;
      case '非Web': return stats.non_web;
      case '官方 Demo': return stats.demo;
      case '完整复现': return stats.repro.success;
      case '部分复现': return stats.repro.partial;
      case '复现中': return stats.repro.in_progress;
      case '待复现': return stats.repro.pending;
      case '复现失败': return stats.repro.failed;
      case '无需复现': return stats.repro.not_supported;
      default: return undefined;
    }
  };

  // 【搜索防抖】搜索框在页头(同时喂明日能力与能力库), 这里 250ms 防抖后再发请求 ——
  // 每敲一键一个请求在隧道上太浪费。
  const [dq, setDq] = useState(search);
  useEffect(() => { const t = setTimeout(() => setDq(search), 250); return () => clearTimeout(t); }, [search]);

  // 【筛选下推服务端】(2026-09-15) 此前是拉 2000 条到浏览器再本地筛: 首屏要付 10.2MB 裸 /
  // 1.39MB gz, 而"分页"发生在下载完之后。现在列表只取 20 条/页, 筛选/搜索都在 SQL 侧做,
  // 且与芯片计数共用同一批谓词(后端 REPRO_PREDICATES), 条数与芯片数字结构性同源。
  const wantWeb = formChips.includes('Web');
  const wantNonWeb = formChips.includes('非Web');
  // 形态沿用"恰选一个才过滤"(两个都不选/都选 = 全部)
  const formParam: LibraryFormKey | null = wantWeb === wantNonWeb ? null : (wantWeb ? 'web' : 'non_web');
  // 【「无需复现」不受形态筛选约束】(2026-10-31): 芯片数字是服务端按 repro_status 全量聚合的
  // (后端谓词已去掉 is_web 前置), 而形态默认只勾 Web —— 再叠一层形态过滤, 就会出现
  // "芯片写 N 条、点进去只有 M 条"。选了它就丢掉形态参数, 让列表与芯片数字同源。
  const effectiveFormParam: LibraryFormKey | null =
    reproChips.includes('无需复现') && formParam === 'web' ? null : formParam;
  // 排序去重后进 query key: 否则 ['Web','非Web'] 与 ['非Web','Web'] 会变成两个缓存条目
  const reproKeys = useMemo(
    () => Array.from(new Set(reproChips.map(c => REPRO_CHIP_KEY[c]).filter((k): k is ReproBucketKey => Boolean(k)))).sort(),
    [reproChips],
  );
  const q = dq.trim();
  const filterKey = `${q}|${effectiveFormParam ?? ''}|${reproKeys.join(',')}`;
  // 【分页重置】依赖必须是"筛选签名"而不是数据引用 —— 若依赖当前页数据, 翻页拿到新数据
  // 会立刻把页码弹回第 1 页(第 2 页永远打不开)。
  useEffect(() => { setPage(1); }, [filterKey]);

  const PAGE_SIZE = 20;
  // 列表视图: 服务端分页, 每页 20 条
  const pageQ = useQuery({
    queryKey: ['cap-library', 'page', filterKey, page],
    queryFn: () => fetchLibraryPage({ q, form: effectiveFormParam, repro: reproKeys, page, page_size: PAGE_SIZE }),
    placeholderData: keepPreviousData,   // 翻页时保留上一页内容, 不闪白
    staleTime: 300_000,
  });
  // 能力分类/应用场景/工程可用性三个视图天然需要整个筛选结果集 → 切过去时才懒加载。
  // 默认的列表视图永远不会发这个请求。
  const showGroups = viewMode !== '列表视图';
  const allQ = useQuery({
    queryKey: ['cap-library', 'all', filterKey],
    queryFn: () => fetchLibraryPage({ q, form: effectiveFormParam, repro: reproKeys, limit: 10000 }),
    enabled: showGroups,
    placeholderData: keepPreviousData,
    staleTime: 300_000,
  });

  const total = pageQ.data?.total ?? 0;
  const pageItems = pageQ.data?.items ?? [];
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  // 筛选变化后页码可能越界(停在第 9 页却只剩 3 页) → 钳到末页, 否则会渲染成空表
  useEffect(() => { if (page > pageCount) setPage(pageCount); }, [page, pageCount]);

  // 【预取下一页】(2026-09-16) 用户走隧道, 一次翻页要付 ~32KB 传输 + 0.2~0.4s 新建连接, 点「下一页」
  // 必等约 2 秒。你还在看第 N 页时, 延后 1.2s(让本页的详情/轮询等前台请求先走)再把第 N+1 页拉进缓存,
  // 点「下一页」就直接从缓存渲染。**只预取一页** —— 不做"把剩下的全拉下来"(那会占满隧道数分钟)。
  useEffect(() => {
    if (showGroups || page >= pageCount) return;
    const timer = setTimeout(() => {
      void qc.prefetchQuery({
        queryKey: ['cap-library', 'page', filterKey, page + 1],   // 必须与 pageQ 的 key 完全一致才会命中缓存
        queryFn: () => fetchLibraryPage({ q, form: effectiveFormParam, repro: reproKeys, page: page + 1, page_size: PAGE_SIZE }),
        staleTime: 300_000,
      });
    }, 1200);
    return () => clearTimeout(timer);
  }, [showGroups, page, pageCount, filterKey, q, effectiveFormParam, reproKeys, qc]);

  const allItems = allQ.data?.items ?? [];
  // 懒查询用 isPending || isFetching 判断: enabled=false 时 v5 的 isLoading 恒为 false,
  // 单看 isLoading 会把"还没开始拉"显示成"空"。
  // 不带 placeholderData 时不加 !allQ.data 条件 —— 改筛选后旧分组仍在屏上, 必须同时给出刷新提示,
  // 否则"芯片说 2 条、面板里还是上一组"这种不一致没有任何提示。
  const loadingAll = showGroups && (allQ.isPending || allQ.isFetching);

  // 【改动 1】能力分类视图：按 capability_type 分组
  const typeGroups = useMemo(() => {
    const g: Record<string, CapabilityItem[]> = {};
    allItems.forEach(item => { const t = item.payload?.capability_type || '未分类'; (g[t] ??= []).push(item); });
    return g;
  }, [allItems]);

  // 【改动 1】应用场景视图：按 application_scenarios 分组
  const scenarioGroups = useMemo(() => {
    const g: Record<string, CapabilityItem[]> = {};
    allItems.forEach(item => { (item.payload?.application_scenarios ?? ['未标注']).forEach(s => { (g[s] ??= []).push(item); }); });
    return g;
  }, [allItems]);

  // 工程可用性视图: 按 reproBucketOf 落桶(判据与后端、与芯片一致), 顺序固定
  const engineeringGroups = useMemo(() => {
    const g: Record<string, CapabilityItem[]> = {};
    for (const bucket of ENGINEERING_BUCKET_ORDER) {
      const list = allItems.filter(i => reproBucketOf(i.payload) === bucket);
      if (list.length > 0) g[ENGINEERING_BUCKET_LABEL[bucket]] = list;
    }
    return g;
  }, [allItems]);

  return <div className="grid">
    <div className="view-switch">
      {(['列表视图', '能力分类', '应用场景', '工程可用性'] as const).map(v => <span key={v} className={`view-pill ${viewMode === v ? 'active' : ''}`} onClick={() => setViewMode(v)}>{v}</span>)}
    </div>
    <div className="view-switch" style={{ marginTop: 8 }}>
      <span style={{ fontSize: 12, color: 'var(--faint)', alignSelf: 'center', whiteSpace: 'nowrap' }}>形态</span>
      {(['Web', '非Web'] as const).map(chip => <span key={chip} className={`view-pill ${formChips.includes(chip) ? 'active' : ''}`} onClick={() => setFormChips(toggleValue(formChips, chip))}>{chip}{chipCount(chip) !== undefined && <em style={{ fontSize: 11, opacity: 0.7, fontStyle: 'normal' }}> {chipCount(chip)}</em>}</span>)}
    </div>
    <div className="view-switch" style={{ marginTop: 8 }}>
      <span style={{ fontSize: 12, color: 'var(--faint)', alignSelf: 'center', whiteSpace: 'nowrap' }}>可体验·复现</span>
      {onlyNonWeb
        ? <span style={{ fontSize: 12, color: 'var(--faint)', alignSelf: 'center' }}>非 Web 条目不参与复现(已被 web 把关挡在复现队列外), 该维度对其不适用</span>
        : (['官方 Demo', '完整复现', '部分复现', '复现中', '待复现', '复现失败', '无需复现'] as const).map(chip => <span key={chip} className={`view-pill ${reproChips.includes(chip) ? 'active' : ''}`} onClick={() => setReproChips(toggleValue(reproChips, chip))}>{chip}{chipCount(chip) !== undefined && <em style={{ fontSize: 11, opacity: 0.7, fontStyle: 'normal' }}> {chipCount(chip)}</em>}</span>)}
    </div>
    {loadingAll && <EmptyState title="正在加载全量" description="分组视图需要整个筛选结果集, 首次切换时拉取一次。" />}
    {/* 空态只在"确实查过且命中 0"时给: 首帧 data 还没到, 单看 total===0 会先闪一下"能力库为空" */}
    {!showGroups && pageQ.isSuccess && total === 0 && <EmptyState title="能力库为空" description="先跑 capabilities.from_news_pipeline 生成能力卡" />}

    {/* 列表视图 */}
    {!showGroups && total > 0 && <div className="table-card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 12px', borderBottom: '1px solid var(--line)', fontSize: 12, color: '#8a94a6' }}>
        <span>共 {total} 条 · 每页 {PAGE_SIZE} 条</span>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button className="btn" disabled={page <= 1 || pageQ.isFetching} onClick={() => setPage(p => Math.max(1, p - 1))}>‹ 上一页</button>
          <span>第 {page}/{pageCount} 页</span>
          <button className="btn" disabled={page >= pageCount || pageQ.isFetching} onClick={() => setPage(p => Math.min(pageCount, p + 1))}>下一页 ›</button>
        </div>
      </div>
      <table className="data-table"><thead><tr><th>能力</th><th>概述</th><th>能力评分</th><th>标签</th></tr></thead><tbody>
      {pageItems.map(item => { const p = item.payload ?? {}; const st = p.source_type || (item.source_url?.includes('github.com') ? 'github' : 'arxiv'); const ov = p.display_summary || p.overview || p.one_liner || ''; return <tr key={item.id} className="clickable" onClick={() => openDetail(item)}>
        <td><div className="table-title">{p.display_title || item.title}</div><div className="table-sub">{st}</div></td>
        <td style={{maxWidth: '320px'}} className="small muted">{ov.slice(0, 120)}{ov.length > 120 ? '…' : ''}</td>
        <td><div className="score-ring">{item.score}</div></td>
        <td><div className="badges">{p.capability_type && <Badge tone="green">{p.capability_type}</Badge>}{showReproBadge(p) && <Badge tone={reproBadgeTone(p.repro_status)}>{reproBadgeLabel(p.repro_status, p.repro_skip_reason)}</Badge>}{p.is_web ? <Badge tone="amber">Web</Badge> : <Badge tone="slate">非Web</Badge>}{p.demo_url && <Badge tone="green">官方 Demo</Badge>}{hasReproResult(p) && <button className="btn" style={{ padding: '1px 8px', fontSize: 11 }} onClick={(e) => { e.stopPropagation(); onViewRepro(item); }}>查看复现 →</button>}</div></td>
      </tr>; })}
    </tbody></table>
    {pageCount > 1 && <div style={{ display: 'flex', justifyContent: 'center', gap: 8, alignItems: 'center', padding: '10px 12px', borderTop: '1px solid var(--line)' }}>
      <button className="btn" disabled={page <= 1 || pageQ.isFetching} onClick={() => setPage(p => Math.max(1, p - 1))}>‹ 上一页</button>
      <span style={{ fontSize: 12, color: '#8a94a6' }}>第 {page}/{pageCount} 页</span>
      <button className="btn" disabled={page >= pageCount || pageQ.isFetching} onClick={() => setPage(p => Math.min(pageCount, p + 1))}>下一页 ›</button>
    </div>}
    </div>}

    {/* 能力分类视图 */}
    {allItems.length > 0 && viewMode === '能力分类' && Object.entries(typeGroups).map(([type, groupItems]) => (
      <div className="panel" key={type}>
        <div className="panel-head"><h3>{type}</h3><span>{groupItems.length} 个</span></div>
        <div className="panel-body"><div className="asis-list">
          {groupItems.map((item, i) => <CapabilityCard key={item.id} item={item} rank={i + 1} onClick={() => openDetail(item)} onRepro={() => {}} onViewRepro={onViewRepro} />)}
        </div></div>
      </div>
    ))}

    {/* 应用场景视图 */}
    {allItems.length > 0 && viewMode === '应用场景' && Object.entries(scenarioGroups).map(([scenario, groupItems]) => (
      <div className="panel" key={scenario}>
        <div className="panel-head"><h3>{scenario}</h3><span>{groupItems.length} 个</span></div>
        <div className="panel-body"><div className="asis-list">
          {groupItems.map((item, i) => <CapabilityCard key={item.id} item={item} rank={i + 1} onClick={() => openDetail(item)} onRepro={() => {}} onViewRepro={onViewRepro} />)}
        </div></div>
      </div>
    ))}

    {/* 工程可用性视图 */}
    {allItems.length > 0 && viewMode === '工程可用性' && <div className="grid cols-2">
      {Object.entries(engineeringGroups).filter(([, groupItems]) => groupItems.length > 0).map(([label, groupItems]) => (
        <div className="panel" key={label}>
          <div className="panel-head"><h3>{label}</h3><span>{groupItems.length} 个</span></div>
          <div className="panel-body"><div className="asis-list">
            {groupItems.length === 0 && <div className="empty-hint">暂无</div>}
            {groupItems.map((item, i) => <CapabilityCard key={item.id} item={item} rank={i + 1} onClick={() => openDetail(item)} onRepro={() => {}} onViewRepro={onViewRepro} />)}
          </div></div>
        </div>
      ))}
    </div>}
  </div>;
}

// ========== 复现验证 ==========
function CapabilityRepro({ runs, openDetail, targetItemId, onTargetConsumed }: { runs: ReproTask[]; openDetail: (item: CapabilityItem) => void; targetItemId?: number | null; onTargetConsumed?: () => void }) {
  const [selectedTaskId, setSelectedTaskId] = useState<number | null>(null);
  const [targetHint, setTargetHint] = useState<string | null>(null);
  // 【跳转复现】从能力库带目标能力进入: 找到对应任务并选中; 队列已加载仍无匹配则提示
  useEffect(() => {
    if (!targetItemId) return;
    const match = runs.find(run => run.item_id === targetItemId);
    if (match) {
      setSelectedTaskId(match.id);
      setTargetHint(null);
      onTargetConsumed?.();
    } else if (runs.length > 0) {
      setTargetHint('该能力暂无对应复现任务, 可回到能力库点「加入复现」触发');
    }
  }, [targetItemId, runs, onTargetConsumed]);
  useEffect(() => {
    if (runs.length > 0 && (selectedTaskId === null || !runs.some(run => run.id === selectedTaskId))) {
      setSelectedTaskId(runs[0].id);
    }
  }, [runs, selectedTaskId]);
  const selected = runs.find(run => run.id === selectedTaskId) ?? runs[0];
  // 【按需取单条】(2026-09-15) 此前是从能力库那份 limit=2000 的列表里 find —— 库内非淘汰条目
  // 已有 2264 条, 排在窗口之外的那些永远查不到, 于是「查看能力详情」按钮静默消失(实测 264 条如此)。
  // 改成按当前选中的任务取该条详情, 只发 1 个请求, 顺带修掉这个隐藏了很久的缺口。
  const { data: capabilityItem } = useQuery({
    queryKey: ['cap-detail', selected?.item_id],
    queryFn: () => fetchDetail(selected!.item_id),
    enabled: Boolean(selected?.item_id),
    staleTime: 300_000,
  });
  const runningCount = runs.filter(run => taskShownStatus(run) === 'running' || taskShownStatus(run) === 'queued').length;
  const successCount = runs.filter(run => ['success', 'partial'].includes(taskShownStatus(run))).length;
  const failedCount = runs.filter(run => ['failed', 'timeout'].includes(taskShownStatus(run))).length;
  // 「无需复现」按成因拆两格(2026-10-31): 非 Web 项目本就不该参与复现维度; 是 Web 但环境缺
  // Docker/KVM 才是「无需复现」。两格之和 = 全部 not_supported 任务。
  const nonWebCount = runs.filter(run => taskShownStatus(run) === 'not_supported' && run.item_repro_skip_reason === 'non_web').length;
  const notSupportedCount = runs.filter(run => taskShownStatus(run) === 'not_supported' && run.item_repro_skip_reason !== 'non_web').length;

  return <div className="grid">
    {targetHint && <div style={{ padding: '8px 12px', marginBottom: 8, borderRadius: 6, border: '1px solid var(--amber, #f5b83d)', background: 'var(--amber-bg, rgba(245,184,61,0.12))', fontSize: 12, color: 'var(--faint)' }}>ℹ {targetHint}</div>}
    {runs.length === 0 && <EmptyState title="暂无复现任务" description="从今日能力或能力库点击「加入复现」触发" />}
    {runs.length > 0 && <>
      <div className="repro-metrics six">
        <div><span>全部任务</span><b>{runs.length}</b></div>
        <div><span>正在复现</span><b className="repro-running">{runningCount}</b></div>
        <div><span>复现成功</span><b className="repro-success">{successCount}</b></div>
        <div><span>失败 / 超时</span><b className="repro-failed">{failedCount}</b></div>
        <div><span>无需复现</span><b className="repro-skipped">{notSupportedCount}</b></div>
        <div><span>非 Web</span><b className="repro-skipped">{nonWebCount}</b></div>
      </div>
      <div className="repro-workbench">
        <div className="panel repro-task-panel">
          <div className="panel-head"><h3>任务队列 ({runs.length})</h3><span>{runningCount > 0 ? '实时更新中' : '历史任务'}</span></div>
          <div className="panel-body repro-task-list">
            {runs.map((run, index) => <button type="button" key={run.id} className={`repro-task ${run.id === selected?.id ? 'active' : ''}`} onClick={() => { setSelectedTaskId(run.id); setTargetHint(null); }}>
              <span className={`repro-status-dot status-${taskShownStatus(run)}`} />
              <span className="repro-task-main">
                <strong>{run.title || run.repo_url?.split('/').filter(Boolean).slice(-1)[0] || `task-${run.id}`}</strong>
                <small>#{run.id} · {run.trigger || 'manual'} · {formatReproTime(run.created_at)}</small>
              </span>
              <span className={`repro-status status-${taskShownStatus(run)}`}>{reproStatusLabel(taskShownStatus(run), run.item_repro_skip_reason)}</span>
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
  const { toast, confirm } = useToast();
  const qc = useQueryClient();
  const [logs, setLogs] = useState<{ line: string; kind: string }[]>([]);
  const [streaming, setStreaming] = useState(false);
  const logRef = useRef<HTMLDivElement>(null);
  const cleanupRef = useRef<(() => void) | null>(null);
  // 二次确认走页面内的弹窗, 不用 window.confirm(跨源 iframe 里会被浏览器吞掉, 点了没反应)
  const [confirmReq, setConfirmReq] = useState<ConfirmRequest | null>(null);
  const { data: taskDetail } = useQuery({
    queryKey: ['cap-repro-task', task.id],
    queryFn: () => fetchReproTask(task.id),
    refetchInterval: task.status === 'running' || task.status === 'queued' ? 2_000 : false,
  });
  const currentTask = taskDetail ?? task;
  // 完整日志(不经 log_excerpt 的 200 行截断):SSE 存活时仅预热一次;
  // SSE 断流/终态后回退到它, 运行中保持轮询追上进度
  const { data: fullLog } = useQuery({
    queryKey: ['cap-repro-full-log', task.id],
    queryFn: () => fetchReproFullLog(task.id),
    // ASIS 反代对 SSE 流 gzip 压缩, 增量事件无法送达浏览器 → SSE 存活时也保持轮询兜底
    refetchInterval: (currentTask.status === 'running' || currentTask.status === 'queued') ? 2_000 : false,
  });
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
            qc.invalidateQueries({ queryKey: ['cap-library-stats'] });
          }
        },
        () => setStreaming(false)
      );
      return () => { cleanupRef.current?.(); };
    } else {
      // 终态: SSE 的 end 事件经 ASIS gzip 可能收不到, 显式结束流, 交由 fullLog 重取接管
      setStreaming(false);
    }
  }, [currentTask.id, currentTask.status, qc]);

  // SSE 断开/结束 → 立即拉一次完整日志兜底(终态内容), 不等轮询
  useEffect(() => {
    if (!streaming) qc.invalidateQueries({ queryKey: ['cap-repro-full-log', task.id] });
  }, [streaming, qc, task.id]);

  useEffect(() => {
    // 流式中或仍在运行(即便 SSE 断了靠轮询续)都自动滚到底部; 终态后不强制, 方便从头看
    if (logRef.current && (streaming || ['running', 'queued'].includes(liveStatus))) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logs, fullLog?.log, streaming, liveStatus]);

  const report = liveReport ?? currentTask.report ?? capabilityItem?.payload?.repro_report;
  const p = capabilityItem?.payload ?? {};
  // 「报告里的 is_web」是 agent 当时的自述, 不是平台分类: 2026-10-29 之前的提示词要求
  // 「项目必须 Docker」时一律报 is_web=false, 于是自带前端的项目(agent-go #10711、kAIm56 #50500)
  // 报告里写「非 Web」, 能力库里却标着 Web。分类以条目 payload 为准, 报告只回答「这轮 Web 服务
  // 起没起来」—— 两个字段分开显示, 不让报告的 is_web 冒充分类结论。
  // 头部徽标同样以条目结论为准(见 taskShownStatus): 否则列表已写「无需复现」, 选中后的控制台还写
  // 「复现失败」。日志流、自动滚动、停止按钮仍按真实任务状态工作 —— 覆盖的只是对外那句话。
  const shownStatus = currentTask.item_repro_status === 'not_supported' ? 'not_supported' : liveStatus;
  // 流式用 SSE 全量; 断流/终态/刷新用完整日志(不再是 log_excerpt 的最后 200 行)
  const fullLogText = fullLog?.log ?? currentTask.log_excerpt ?? currentTask.result ?? '';
  const displayedLogs = streaming && logs.length > 0 ? logs : fullLogText.split('\n').filter(Boolean).map(line => ({ line: stripAnsi(line), kind: classifyLogLine(line) }));

  return <div className="repro-console">
    <div className="repro-console-head">
      <div><span className={`repro-status status-${shownStatus}`}>{reproStatusLabel(shownStatus, currentTask.item_repro_skip_reason)}</span><strong>{currentTask.repo_url?.split('/').filter(Boolean).slice(-1)[0]}</strong></div>
      <div className="repro-meta">任务 #{currentTask.id}{currentTask.web_port ? ` · Web ${currentTask.web_port}` : ''}</div>
    </div>
    <div className="repro-actions">
      {p.demo_url && <a className="btn primary" href={p.demo_url} target="_blank" rel="noreferrer">打开官方 Demo ↗</a>}
      {!p.demo_url && currentTask.web_url && report?.web_started && <a className="btn primary" href={currentTask.web_url} target="_blank" rel="noreferrer">打开 Web 验证 ↗</a>}
      {!p.demo_url && p.repro_status !== 'not_supported' && <button className="btn primary" onClick={() => {
        if (!capabilityItem) return;
        setConfirmReq({
          title: `重跑条目 #${capabilityItem.id} 的复现？`,
          message: <>会在复现沙箱里新建一条任务，重新 clone、装依赖、起服务；当前这条任务的记录保留不动。<br />同时能跑的复现有上限，名额满时会先排队，等前面那条结束再开始。</>,
          confirmLabel: '重跑',
          onConfirm: async () => {
            try { await startRepro(capabilityItem.id, p.is_web ?? false); toast('已重跑复现', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } catch (e) { toast(`重跑失败: ${e}`, 'error'); }
          },
        });
      }}>重跑</button>}
      {['running', 'queued'].includes(liveStatus) && <button className="btn" onClick={() => setConfirmReq({
        title: `停止任务 #${currentTask.id}？`,
        message: '复现会立刻中止，这一轮不再产出结论（工作目录和日志保留，之后可以「重跑」）。',
        confirmLabel: '停止',
        onConfirm: async () => {
          try { await stopRepro(currentTask.id); toast('已停止', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } catch (e) { toast(`停止失败: ${e}`, 'error'); }
        },
      })}>停止</button>}
      {/* 清理不可撤销: 任务作废 + 复现卷里的 clone/venv/服务进程由 repro 看门狗回收, 条目没有其它
          任务时结论还会复位成「待复现」—— 手滑一下就得从头再跑, 所以先要一次确认(2026-10-29)。 */}
      <button className="btn" onClick={() => setConfirmReq({
        title: `清理任务 #${currentTask.id}？`,
        message: <>这条任务会被作废，它的 clone / venv / 服务进程由复现看门狗回收（约 2 分钟内）。<br />若该条目没有其它任务，复现结论会复位为「待复现」，需要从头再跑。</>,
        confirmLabel: '清理',
        danger: true,
        onConfirm: async () => {
          try { await cleanupRepro(currentTask.id); toast('已清理', 'success'); qc.invalidateQueries({ queryKey: ['cap-repro'] }); } catch (e) { toast(`清理失败: ${e}`, 'error'); }
        },
      })}>清理</button>
      {capabilityItem && <button className="btn" onClick={() => openDetail(capabilityItem)}>查看能力详情</button>}
    </div>
    <ConfirmModal request={confirmReq} onClose={() => setConfirmReq(null)} />
    <section className="repro-section">
      <div className="repro-section-title"><span>执行日志</span><small>{streaming && logs.length > 0 ? 'SSE LIVE' : `全文 ${displayedLogs.length} 行`}</small></div>
      <div className="log-stream" ref={logRef}>{displayedLogs.map((log, index) => <div key={`${index}-${log.line}`} className={`log-line log-${log.kind}`}>{log.line}</div>)}{displayedLogs.length === 0 && <div className="muted small">{liveStatus === 'queued' ? '任务已排队，等待复现调度…' : (!taskDetail && !fullLog ? '正在载入日志…' : '等待日志输出…')}</div>}</div>
    </section>
    {report && <>
      <section className="repro-section">
        <div className="repro-section-title"><span>复现结论</span><small>{report.level || report.web_framework || report.project_type || '自动报告'}</small></div>
        <div className={`repro-summary ${report.status === 'success' ? 'success' : report.status === 'partial' ? 'partial' : 'failed'}`}><strong>{report.summary || '暂无摘要'}</strong>{report.verify && <p>验证：{report.verify}</p>}{report.status === 'partial' && <p>部分可用：{report.partial_reason || 'agent 未说明哪一部分有问题'}</p>}</div>
        <div className="field-grid repro-fields">
          <div className="cap-field"><span>报告状态</span><b>{reproStatusLabel(report.status)}</b></div>
          <div className="cap-field"><span>项目类型</span><b>{report.web_framework || report.project_type || '-'}</b></div>
          <div className="cap-field"><span>Web 分类</span><b>{p.is_web === true ? (p.web_framework ? `Web（${p.web_framework}）` : 'Web') : p.is_web === false ? '非 Web' : '未分类'}</b></div>
          <div className="cap-field"><span>Web 启动</span><b>{report.web_started ? '已启动并验证' : report.is_web === false && p.is_web === true ? '未启动（项目是 Web，本环境未跑起来）' : report.is_web === false ? '未启动（agent 判定本项目没有 Web 界面）' : '未启动'}</b></div>
          <div className="cap-field"><span>启动命令</span><code>{report.start_command || '-'}</code></div>
          <div className="cap-field"><span>构建证据</span><code>{report.build?.command ? `${report.build.command}${report.build.exit_code === undefined ? '' : ` · exit ${report.build.exit_code}`}${report.build.artifact ? ` · 产物 ${report.build.artifact}` : ''}` : '-'}</code></div>
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
      {(report.page_check || report.tests) && <section className="repro-section">
        <div className="repro-section-title"><span>页面自检与仓库测试</span><small>{report.page_check ? (report.page_check.ok === false ? '页面打不开' : report.page_check.ok ? '页面已校验' : '未完成自检') : '未自检'}</small></div>
        {report.page_check && <div className="field-grid repro-fields">
          <div className="cap-field"><span>页面自检</span><b>{report.page_check.ok === false ? '未通过' : report.page_check.ok ? '通过' : '未完成'}</b></div>
          <div className="cap-field"><span>首页状态</span><b>{report.page_check.entry_status ?? '-'}{report.page_check.entry_type ? ` · ${report.page_check.entry_type}` : ''}</b></div>
          <div className="cap-field"><span>入口资源</span><b>{report.page_check.resources_checked ?? 0} 个已校验{(report.page_check.failed?.length ?? 0) > 0 ? `，${report.page_check.failed?.length} 个失败` : ''}</b></div>
          <div className="cap-field"><span>可见正文</span><b>{report.page_check.visible_chars ?? 0} 字符</b></div>
        </div>}
        {report.tests && <div className={`repro-summary ${report.tests.result === 'pass' ? 'success' : report.tests.result === 'fail' ? 'failed' : 'partial'}`}>
          <strong>{TEST_RESULT_LABEL[report.tests.result ?? ''] ?? report.tests.result ?? '测试未执行'}</strong>
          <p>测试框架：{report.tests.framework || '-'}{report.tests.command ? ` · 命令：${report.tests.command}` : ''}</p>
          {report.tests.totals && <p>通过 {report.tests.totals.passed ?? 0} / 失败 {report.tests.totals.failed ?? 0} / 跳过 {report.tests.totals.skipped ?? 0}</p>}
          {(report.tests.fixed?.length ?? 0) > 0 && <p>为跑通测试做的修复：{report.tests.fixed?.join('；')}</p>}
          {(report.tests.failed_tests?.length ?? 0) > 0 && <p>失败用例：{report.tests.failed_tests?.join('；')}</p>}
          {report.tests.notes && <p>说明：{report.tests.notes}</p>}
        </div>}
        {(report.page_check?.issues?.length ?? 0) > 0 && <div className="repro-findings">
          {(report.page_check?.issues ?? []).map((issue, index) => <div className="blocker" key={`pagecheck-${index}`}>页面自检：{issue}</div>)}
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

/** 任务行该显示成什么: 所属能力条目已被判「无需复现」时, 覆盖任务行的原始结果。
 *
 *  2026-10-29: 同一件事在两页说法不一 —— 能力库写「无需复现」, 复现页还按任务行的 failed/success
 *  显示「复现失败」/「复现成功」。结论在能力条目上(item_repro_status, 后端 /repro-runs 与
 *  /repro/{id} 一并带回), 任务行只是执行记录, 所以展示层以结论为准; 原始状态仍可在详情里追。 */
function taskShownStatus(task: { status: string; item_repro_status?: string }): string {
  return task.item_repro_status === 'not_supported' ? 'not_supported' : task.status;
}

const TEST_RESULT_LABEL: Record<string, string> = {
  pass: '测试通过',
  partial: '测试部分通过(有失败用例)',
  fail: '测试失败',
  skipped: '测试未运行(环境不允许)',
  not_found: '仓库没有测试',
};

function reproStatusLabel(status: string, skipReason?: string): string {
  if (status === 'not_supported') return reproNotSupportedLabel(skipReason);
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
function CapabilityDetailContent({ itemId, initialItem, onRepro, onConvert, onViewRepro }: { itemId: number; initialItem: CapabilityItem; onRepro: () => void; onConvert: (data: ConvertFormData) => Promise<void>; onViewRepro?: (item: CapabilityItem) => void }) {
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
  // 复现结论原文(取自复现结果 repro_result.summary, 如 AutoCVE 的 FAILURE 判定说明)
  const reproReason = p.repro_result && typeof p.repro_result === 'object' ? (p.repro_result as { summary?: string }).summary : undefined;

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
    <div className="drawer-section"><h3>复现 & 转化</h3><div className="badges">{showReproBadge(p) && <Badge tone={reproBadgeTone(p.repro_status)}>{reproBadgeLabel(p.repro_status, p.repro_skip_reason)}</Badge>}<Badge tone="violet">{p.conversion_status ?? '待评估'}</Badge>{p.is_web ? <Badge tone="amber">Web{p.web_framework ? `:${p.web_framework}` : ''}</Badge> : <Badge tone="slate">非Web</Badge>}{p.demo_url && <Badge tone="green">官方 Demo</Badge>}</div></div>

    {/* 无需复现说明(2026-10-29): 徽标只写「无需复现」, 为什么不需要放在这里 —— 两种原因互不相干,
        合成一句话就会两种都说错。旧数据没有 repro_skip_reason 时按 Docker 口径兜底(那是这个终态
        最初的唯一来源)。 */}
    {p.repro_status === 'not_supported' && <div className="drawer-section"><h3>复现说明</h3><p style={{ color: 'var(--muted, #8a8f98)' }}>{p.repro_skip_reason === 'non_web'
      ? '复现结论判定这个项目不是 Web 应用（没有浏览器界面），复现维度对它不适用 —— 不是复现失败，也不会进入复现队列。'
      : '项目依赖 Docker 等本环境没有的运行条件，按平台规则判定为「无需复现」，不进入复现队列。这是环境边界，不是项目本身复现不出来。'}</p>{reproReason && <blockquote style={{ margin: '8px 0 0', padding: '8px 12px', background: 'rgba(127,127,127,.07)', borderLeft: '3px solid rgba(127,127,127,.5)', fontSize: 12 }}>{reproReason}</blockquote>}</div>}

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
      {!p.demo_url && p.is_web && p.repro_status !== 'not_supported' && <button className="pill-button primary" onClick={onRepro}>加入复现</button>}
      {hasReproResult(p) && onViewRepro && <button className="pill-button" onClick={() => onViewRepro(item ?? initialItem)}>查看复现结果</button>}
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
