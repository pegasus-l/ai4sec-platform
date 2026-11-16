import { useEffect, useState } from 'react';
import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Badge, EmptyState } from '../../components/ui';
import { useDrawerStack } from '../../components/DrawerStack';
import { useToast } from '../../components/Toast';
import { CommandBlock, WriteupTaskDrawer } from './WriteupTaskDrawer';
import { createTask, fetchPatterns, fetchRecipes, fetchStats, fetchTasks } from './writeupReproQueries';
import type { WriteupPatternRow, WriteupRecipeRow, WriteupTask } from './writeupReproTypes';
import {
  failureLabel, fmtDuration, fmtTime, listOf, statusMeta, triggerLabel, verdictMeta,
} from './writeupReproLabels';

/**
 * writeup 复现 —— 把一篇漏洞 writeup **真的跑一遍**, 留下证据、八节报告与可复用的配方/规律。
 *
 * 这一页最容易犯的三个错, 逐条挡在代码里:
 *  1. 把 `cannot_repro`(原文没写清) 与 `failed`(我们的环境起不来) 合成一个"失败"数字 ——
 *     两个方向的责任, 统计与筛选都分开, 不提供合并口径。
 *  2. 把"还没跑 / 没报告 / 没产物"显示成空 —— 每一种都有一句"为什么现在是空的",
 *     以及下一步该点哪个按钮。
 *  3. 页面上出现的结论点不到证据 —— 报告 tab 的每一步、recipe 的每一条命令都带报告第 3 节的
 *     命令序号, 数字点开就是命令原文。
 */

const PAGE_SIZE = 20;
const ACTIVE_STATUSES = ['pending', 'spec_ready', 'queued', 'running'];

/** 顶部统计 = 筛选按钮。六格对应六种"我现在想看哪一批", 点一下就是一次服务端查询。 */
function StatChip({ label, value, hint, active, onClick }: { label: string; value: number; hint?: string; active: boolean; onClick: () => void }) {
  return <button type="button" className={`case-stat-chip ${active ? 'active' : ''}`} title={hint} onClick={onClick}>
    <span className="case-stat-chip-label">{label}</span>
    <b>{value}</b>
  </button>;
}

/** 三件产物有没有。用与案例库同一套 .context-dots —— 它本来就是"哪一格有"的语义。 */
function ProductDots({ products }: { products?: WriteupTask['products'] }) {
  const bits: Array<[string, boolean, string]> = [
    ['报', Boolean(products?.report), '八节复现报告'],
    ['方', Boolean(products?.recipe), '配方:这一类怎么跑'],
    ['律', Boolean(products?.pattern), '规律:这一类怎么找'],
  ];
  return <div className="context-dots">
    {bits.map(([label, on, title]) => <span key={label} className={`context-dot ${on ? 'on' : ''}`} title={`${title}: ${on ? '已有' : '没有'}`}>{label}</span>)}
  </div>;
}

type Tab = 'tasks' | 'recipes' | 'patterns';

export function WriteupRepro({ focusTaskId, onFocusConsumed }: { focusTaskId?: number | null; onFocusConsumed?: () => void }) {
  const [tab, setTab] = useState<Tab>('tasks');
  const [verdict, setVerdict] = useState('');
  const [activeOnly, setActiveOnly] = useState(false);
  const [status, setStatus] = useState('');
  const [offset, setOffset] = useState(0);
  const [materialId, setMaterialId] = useState('');
  // 默认按素材折叠: 重跑是 attempt+1 新开一行, 不平铺的话一篇 writeup 跑三遍就是三张
  // 标题一样的卡 —— 用户读到的是"三个 writeup"。
  const [folded, setFolded] = useState(true);
  const { push } = useDrawerStack();
  const { toast } = useToast();
  const qc = useQueryClient();

  const stats = useQuery({ queryKey: ['writeup', 'stats'], queryFn: fetchStats, refetchInterval: 30_000 });
  const list = useQuery({
    queryKey: ['writeup', 'tasks', { verdict, activeOnly, status, folded, offset }],
    queryFn: () => fetchTasks({
      verdict: verdict || undefined,
      active: activeOnly ? true : undefined,
      status: status || undefined,
      latestOnly: folded,
      limit: PAGE_SIZE,
      offset,
    }),
    placeholderData: keepPreviousData,
    // 有未结束的任务才轮询 —— 全终结时每 10 秒打一次库只是噪声。
    refetchInterval: query => {
      const items = (query.state.data as { items?: WriteupTask[] } | undefined)?.items ?? [];
      return items.some(item => ACTIVE_STATUSES.includes(item.status)) ? 8_000 : 60_000;
    },
  });

  // 换筛选必须回第一页, 否则会停在新结果集里越界的 offset 上(页面看着像空了)。
  useEffect(() => { setOffset(0); }, [verdict, activeOnly, status, folded]);

  const openTask = (task: WriteupTask) => push({
    title: task.material?.title || `复现任务 #${task.id}`,
    subtitle: `#${task.id} · 第 ${task.attempt} 遍 · ${statusMeta(task.status).label}`,
    render: () => <WriteupTaskDrawer taskId={task.id} />,
  });

  /** 折叠视图里点历史条 = 打开**那一遍**的抽屉(证据、报告都挂在遍上, 不是挂在素材上)。 */
  const openAttempt = (attemptId: number, attempt: number, taskStatus: string) => push({
    title: `复现任务 #${attemptId}`,
    subtitle: `第 ${attempt} 遍 · ${statusMeta(taskStatus).label}`,
    render: () => <WriteupTaskDrawer taskId={attemptId} />,
  });

  // 从素材抽屉点「复现这篇」跳进来: 直接把那一条的抽屉打开(落地就是 "对应条目")。
  const [focused, setFocused] = useState(false);
  useEffect(() => {
    if (focused || !focusTaskId) return;
    setFocused(true);
    push({
      title: `复现任务 #${focusTaskId}`,
      render: () => <WriteupTaskDrawer taskId={focusTaskId} />,
    });
    onFocusConsumed?.();
  }, [focusTaskId, focused, push, onFocusConsumed]);

  const create = useMutation({
    mutationFn: (id: number) => createTask(id),
    onSuccess: result => {
      toast(result.created ? `已建任务 #${result.task.id}（素材 ${result.task.material_id}）` : `素材 ${result.task.material_id} 已有任务 #${result.task.id}，直接打开`, 'success');
      setMaterialId('');
      void qc.invalidateQueries({ queryKey: ['writeup'] });
      openTask(result.task);
    },
    onError: error => toast(`建任务失败（${(error as Error)?.message ?? error}）：素材必须是已有的漏洞素材 id`, 'error'),
  });

  const items = list.data?.items ?? [];
  const total = list.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const kpi = stats.data;
  const hasFilter = Boolean(verdict || activeOnly || status);
  const apply = (next: { verdict?: string; active?: boolean; status?: string }) => {
    setVerdict(next.verdict ?? '');
    setActiveOnly(next.active ?? false);
    setStatus(next.status ?? '');
  };
  const isOn = (next: { verdict?: string; active?: boolean; status?: string }) =>
    verdict === (next.verdict ?? '') && activeOnly === (next.active ?? false) && status === (next.status ?? '');

  // 折叠视图上芯片必须数**素材**, 不是数遍: 卡片只有一张, 芯片写 3 会让用户以为筛选坏了。
  const verdictCount = (key: string) =>
    (folded ? kpi?.by_verdict_materials?.[key] : kpi?.by_verdict?.[key]) ?? 0;
  const totalCount = (folded ? kpi?.materials : kpi?.total) ?? 0;
  const activeCount = (folded ? kpi?.active_materials : kpi?.active) ?? 0;

  return <div className="v11-view">
    <section className="panel case-stat-strip">
      <div className="case-stat-row">
        <StatChip label={folded ? '素材（已折叠）' : '全部任务'} value={totalCount} active={isOn({})} onClick={() => apply({})} hint={folded ? `一篇 writeup 一行，共 ${kpi?.total ?? 0} 遍任务` : '一行 = 把一篇 writeup 跑一遍；同一篇跑多遍就多行'} />
        <StatChip label="进行中" value={activeCount} active={isOn({ active: true })} onClick={() => apply({ active: true })} hint="还没结束：待 spec / spec 就绪 / 排队 / 执行中" />
        <StatChip label="复现成功" value={verdictCount('success')} active={isOn({ verdict: 'success' })} onClick={() => apply({ verdict: 'success' })} hint="判据命中且证据无缺口" />
        <StatChip label="部分复现" value={verdictCount('partial')} active={isOn({ verdict: 'partial' })} onClick={() => apply({ verdict: 'partial' })} hint="跑到了，但判据没完全命中或证据有缺口" />
        <StatChip label="原文不可复现" value={verdictCount('cannot_repro')} active={isOn({ verdict: 'cannot_repro' })} onClick={() => apply({ verdict: 'cannot_repro' })} hint="原文的问题：没写清攻击过程 / 版本对不上 —— 不是我们没做出来" />
        <StatChip label="执行失败" value={verdictCount('failed')} active={isOn({ verdict: 'failed' })} onClick={() => apply({ verdict: 'failed' })} hint="我们的问题：环境没起来 / 执行异常" />
      </div>
      <div className="case-mini-foot">
        <button className={`view-pill ${tab === 'tasks' ? 'active' : ''}`} onClick={() => setTab('tasks')}>任务 {kpi?.total ?? 0}</button>
        <button className={`view-pill ${tab === 'recipes' ? 'active' : ''}`} onClick={() => setTab('recipes')}>配方 {kpi?.products.recipes ?? 0}</button>
        <button className={`view-pill ${tab === 'patterns' ? 'active' : ''}`} onClick={() => setTab('patterns')}>规律 {kpi?.products.patterns ?? 0}</button>
        {tab === 'tasks' && <select value={status} onChange={event => { setStatus(event.target.value); setVerdict(''); setActiveOnly(false); }}>
          <option value="">全部状态</option>
          <option value="pending">待生成 spec</option>
          <option value="spec_ready">spec 就绪</option>
          <option value="queued">排队中</option>
          <option value="running">执行中</option>
          <option value="cancelled">已取消</option>
          <option value="spec_failed">spec 生成失败</option>
        </select>}
      </div>
    </section>

    {tab === 'tasks' && <CoverageNote />}

    {tab === 'tasks' && <>
      <section className="panel">
        <div className="panel-head">
          <h3>复现任务</h3>
          <span>{folded
            ? '一篇 writeup 一行；同一篇跑过多遍时，卡片上列出每一遍的结论，点进去看那一遍的证据'
            : '一条任务 = 一篇 writeup 的一次真实执行；证据、报告、配方都挂在它下面'}</span>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <label className="small muted" style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }} title="重跑会新开一行；折叠后一个素材只留符合当前筛选的最后一遍">
              <input type="checkbox" checked={folded} onChange={event => setFolded(event.target.checked)} />
              每个素材一行
            </label>
            <input className="search" placeholder="按素材 ID 建任务" value={materialId}
              onChange={event => setMaterialId(event.target.value.replace(/\D/g, ''))}
              onKeyDown={event => { if (event.key === 'Enter' && materialId) create.mutate(Number(materialId)); }}
              style={{ width: 150 }} />
            <button className="btn" disabled={!materialId || create.isPending} onClick={() => create.mutate(Number(materialId))}>
              {create.isPending ? '建任务中…' : '+ 建任务'}
            </button>
          </div>
        </div>
        <div className="panel-body">
          {list.isLoading
            ? <p className="muted small">正在读取任务…</p>
            : items.length
              ? <div className="case-list">{items.map(task => <TaskCard key={task.id} task={task} onOpen={() => openTask(task)} onOpenAttempt={openAttempt} />)}</div>
              : <EmptyState
                title={hasFilter ? '没有匹配的任务' : '还没有复现任务'}
                description={hasFilter
                  ? '换个筛选试试。' + (verdict === 'success' ? '「复现成功」不是默认结果 —— 大部分 writeup 只能做到 partial，或卡在环境上。' : '')
                  : '在「漏洞洞察 → 情报素材」里挑一篇讲清根因的 writeup，点「复现这篇」；也可以在上面输入素材 ID 直接建。'}
              />}
        </div>
      </section>
      <Pagination page={page} pages={pages} total={total} setOffset={setOffset} />
    </>}

    {tab === 'recipes' && <RecipesTab />}
    {tab === 'patterns' && <PatternsTab />}
  </div>;
}

/**
 * 收录范围(T6.4)。**没这段, 用户会把"这里没有"读成"这篇不值得复现"** —— 比收不全更危险。
 * 数字来自 T1.4 的实跑基线(1229 条素材 / rules-v2), 不是估计值。
 */
function CoverageNote() {
  return <p className="muted small" style={{ margin: '4px 0 10px', lineHeight: 1.75 }}>
    收录范围：只收<b>讲清根因、且有具体触发过程</b>的漏洞 writeup。素材先过规则层（有没有 PoC、目标是否明确、正文是否足够），
    再过模型层（是不是一篇能照着跑的东西），1229 篇里最后进复现队列 102 篇（8.3%）；其中仓库 + 版本都写明的严格口径只有 15 篇。
    未收录：纯教程 / 清单页 / 新闻体、没有可运行 PoC 的分析文、以及只提了一句 CVE 编号的综述 —— 这里查不到某篇文章不等于它没价值，只是它没进这条流水线。
    <span style={{ display: 'block', marginTop: 4 }}>
      结果口径：<b>原文不可复现</b>是原文没写清（作者的问题），<b>执行失败</b>是我们的环境没起来（我们的问题），两者分开统计；
      <b>被安全边界拦下</b>是执行里出现了对公网目标的真实请求，平台主动终止 —— 这三类都不是"这篇写错了"。
    </span>
  </p>;
}

function TaskCard({ task, onOpen, onOpenAttempt }: {
  task: WriteupTask;
  onOpen: () => void;
  onOpenAttempt: (attemptId: number, attempt: number, taskStatus: string) => void;
}) {
  const status = statusMeta(task.status);
  const verdict = task.verdict ? verdictMeta(task.verdict) : null;
  const title = task.material?.title || task.claim || `复现任务 #${task.id}`;
  // 标题已经是文章标题时, 正文不要再复述一遍 claim; 标题缺失时 claim 就是标题。
  const subtitle = task.material?.title && task.claim ? `「${task.claim}」` : '';
  const history = task.attempts ?? [];
  return <article className="case-card clickable" onClick={onOpen}>
    <div className="case-card-main">
      <div className="badges">
        <Badge tone={status.tone}>{status.label}</Badge>
        {verdict && <Badge tone={verdict.tone}>{verdict.label}</Badge>}
        {task.failure_reason && <Badge tone="slate">{failureLabel(task.failure_reason)}</Badge>}
        {history.length > 1
          ? <Badge tone="violet">共 {history.length} 遍</Badge>
          : task.attempt > 1 ? <Badge tone="violet">第 {task.attempt} 遍</Badge> : null}
        <Badge tone="slate">素材 #{task.material_id}</Badge>
      </div>
      <h4>{title}</h4>
      {subtitle && <p>{subtitle}</p>}
      {/* 折叠后一行代表多遍 —— 每一遍的结论都得看得见, 否则"这篇到底跑成过没有"要靠切筛选去猜。
          点某一遍打开的是**那一遍**的抽屉: 证据和报告挂在遍上, 不在素材上。 */}
      {history.length > 1 && <div className="case-mini-foot" style={{ gap: 6, flexWrap: 'wrap' }}>
        {history.map(item => {
          const meta = statusMeta(item.status);
          const current = item.id === task.id;
          return <button
            key={item.id}
            className={`view-pill ${current ? 'active' : ''}`}
            style={{ fontSize: 11, padding: '1px 6px' }}
            title={`#${item.id} · ${meta.label}${item.failure_reason ? ` · ${failureLabel(item.failure_reason)}` : ''} · ${fmtTime(item.finished_at || item.created_at)}`}
            onClick={event => { event.stopPropagation(); onOpenAttempt(item.id, item.attempt, item.status); }}
          >第 {item.attempt} 遍 · {item.verdict ? verdictMeta(item.verdict).label : meta.label}</button>;
        })}
      </div>}
      <p className="small">
        {[task.target_repo, task.target_version].filter(Boolean).join(' · ') || '目标未在原文里写明'}
        {task.material?.url ? ' · 原文已关联' : task.material === null ? ' · 原文已查不到' : ''}
      </p>
      <div className="case-mini-foot">
        <span className="muted small">{triggerLabel(task.trigger)} · {fmtTime(task.created_at)}</span>
        {task.status === 'running' && <Badge tone="sky">正在跑</Badge>}
        {task.products?.report === false && !ACTIVE_STATUSES.includes(task.status) && <span className="muted small">无报告</span>}
      </div>
    </div>
    <div className="case-card-side">
      <ProductDots products={task.products} />
      <b>{fmtDuration(task.duration_seconds)}</b>
      <span className="small muted">{task.tool_calls ?? 0} 次工具调用</span>
      {/* 回到文章本身。新开一个页签: 用户多半是想边看原文边对照这条任务的结论, 不该丢掉列表位置。 */}
      <a
        className="btn"
        href={`/insights/vulnerabilities?material=${task.material_id}`}
        target="_blank"
        rel="noreferrer"
        onClick={event => event.stopPropagation()}
      >原文</a>
      <button className="btn primary" onClick={event => { event.stopPropagation(); onOpen(); }}>看证据</button>
    </div>
  </article>;
}

// ========== 配方 ==========

function RecipesTab() {
  const [degradedOnly, setDegradedOnly] = useState(false);
  const [offset, setOffset] = useState(0);
  useEffect(() => { setOffset(0); }, [degradedOnly]);
  const query = useQuery({
    queryKey: ['writeup', 'recipes', { degradedOnly, offset }],
    queryFn: () => fetchRecipes({ degraded: degradedOnly ? true : undefined, limit: PAGE_SIZE, offset }),
    placeholderData: keepPreviousData,
  });
  const items = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  return <>
    <section className="panel">
      <div className="panel-head">
        <h3>配方 · 这一类怎么跑</h3>
        <span>每条命令都能回指报告第 3 节的命令序号；只从 success（或标了降级的 partial）里抽</span>
        <button className={`view-pill ${degradedOnly ? 'active' : ''}`} onClick={() => setDegradedOnly(value => !value)}>只看降级</button>
      </div>
      <div className="panel-body">
        {query.isLoading
          ? <p className="muted small">正在读取配方…</p>
          : items.length
            ? <div className="case-list">{items.map(recipe => <RecipeCard key={recipe.id} recipe={recipe} />)}</div>
            : <EmptyState
              title={degradedOnly ? '没有降级配方' : '还没有可复用的配方'}
              description="配方在任务终结时从报告里抽：只有复现成功（或部分成功）的执行才有可复用的路径。failed / blocked / 原文不可复现 都不出配方 —— 那是事实，不是抽取失败。"
            />}
      </div>
    </section>
    <Pagination page={page} pages={pages} total={total} setOffset={setOffset} />
  </>;
}

function RecipeCard({ recipe }: { recipe: WriteupRecipeRow }) {
  const body = recipe.recipe_json ?? {};
  const fingerprint = listOf(body.applies_to?.fingerprint ?? recipe.fingerprint_json);
  const commandCount = (body.acquire?.length ?? 0) + (body.setup?.length ?? 0) + (body.trigger?.length ?? 0) + (body.probe ? 1 : 0);
  return <article className="case-card">
    <div className="case-card-main">
      <div className="badges">
        {fingerprint.map(item => <Badge key={item} tone="sky">{item}</Badge>)}
        {recipe.degraded && <Badge tone="amber">降级（来自 partial）</Badge>}
        <Badge tone="slate">{commandCount} 条命令</Badge>
      </div>
      <h4>{body.target?.repo ? String(body.target.repo) : recipe.recipe_key}</h4>
      <p className="small">
        来源：任务 #{recipe.task_id} · 素材 #{recipe.material_id} · {fmtTime(recipe.created_at)}
        {body.source?.verdict ? ` · 结论 ${body.source.verdict}` : ''}
      </p>
      <details style={{ marginTop: 8 }}>
        <summary className="small muted" style={{ cursor: 'pointer' }}>展开命令</summary>
        {[['取得目标', body.acquire ?? []], ['准备环境', body.setup ?? []], ['触发', body.trigger ?? []]].map(([title, steps]) =>
          (steps as RecipeStepLike[]).length === 0 ? null : <div key={String(title)} style={{ marginTop: 8 }}>
            <p className="small" style={{ margin: '0 0 4px' }}><b>{String(title)}</b></p>
            {(steps as RecipeStepLike[]).map((step, index) => <CommandBlock key={`${String(title)}-${index}`} command={{ index: step.index ?? undefined, cmd: step.cmd, exit_code: step.exit_code ?? undefined }} />)}
          </div>)}
        {body.probe ? <div style={{ marginTop: 8 }}>
          <p className="small" style={{ margin: '0 0 4px' }}><b>probe</b></p>
          <CommandBlock command={{ index: body.probe.index ?? undefined, cmd: body.probe.cmd ?? '', exit_code: body.probe.exit_code ?? undefined }} />
          {body.probe.success_signal && <p className="muted small" style={{ margin: '6px 0 0' }}>判据：{body.probe.success_signal}</p>}
        </div> : null}
      </details>
    </div>
    <div className="case-card-side">
      <b>{body.source?.duration_seconds != null ? fmtDuration(Number(body.source.duration_seconds)) : '—'}</b>
      <span className="small muted">当时耗时</span>
    </div>
  </article>;
}

type RecipeStepLike = { index?: number | null; cmd: string; exit_code?: number | null };

// ========== 规律 ==========

const GENERALIZATION_LABELS: Record<string, string> = { framework: '框架内', language: '语言内', generic: '跨语言' };

function PatternsTab() {
  const [generalization, setGeneralization] = useState('');
  const [offset, setOffset] = useState(0);
  useEffect(() => { setOffset(0); }, [generalization]);
  const query = useQuery({
    queryKey: ['writeup', 'patterns', { generalization, offset }],
    queryFn: () => fetchPatterns({ generalization: generalization || undefined, limit: PAGE_SIZE, offset }),
    placeholderData: keepPreviousData,
  });
  const items = query.data?.items ?? [];
  const total = query.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const page = Math.floor(offset / PAGE_SIZE) + 1;
  return <>
    <section className="panel">
      <div className="panel-head">
        <h3>规律 · 这一类怎么找</h3>
        <span>门槛是报告第 6 节通过校验（漏洞点在原文里对得上），与复现成没成无关</span>
        <div className="view-pills">
          {[['', '全部'], ['framework', '框架内'], ['language', '语言内'], ['generic', '跨语言']].map(([id, label]) =>
            <button key={id} className={`view-pill ${generalization === id ? 'active' : ''}`} onClick={() => setGeneralization(id)}>{label}</button>)}
        </div>
      </div>
      <div className="panel-body">
        {query.isLoading
          ? <p className="muted small">正在读取规律…</p>
          : items.length
            ? <div className="case-list">{items.map(pattern => <PatternCard key={pattern.id} pattern={pattern} />)}</div>
            : <EmptyState
              title="还没有入库的规律"
              description="规律要求第 7 节通过入库闸门：有不变量、泛化边界合法、三种可执行形态齐全、且第 6 节的漏洞点已在原文里校验过。复现失败不影响它 —— 原文把根因讲透了就能出规律。"
            />}
      </div>
    </section>
    <Pagination page={page} pages={pages} total={total} setOffset={setOffset} />
  </>;
}

function PatternCard({ pattern }: { pattern: WriteupPatternRow }) {
  return <article className="case-card">
    <div className="case-card-main">
      <div className="badges">
        <Badge tone="violet">{GENERALIZATION_LABELS[pattern.generalization] ?? pattern.generalization}</Badge>
        {pattern.confidence != null && <Badge tone="sky">置信度 {Math.round(pattern.confidence * 100)}%</Badge>}
        {listOf(pattern.fingerprint).map(item => <Badge key={item} tone="slate">{item}</Badge>)}
      </div>
      <h4>{pattern.invariant}</h4>
      {pattern.code_feature && <p>代码特征：{pattern.code_feature}</p>}
      <p className="small">
        {pattern.audit_entry ? `审计入口：${pattern.audit_entry}` : ''}
        {pattern.discriminator ? ` · 判别点：${pattern.discriminator}` : ''}
      </p>
      <div className="case-mini-foot">
        <span className="muted small">来源任务 #{pattern.report_id} · 素材 #{pattern.material_id} · {pattern.provenance} · {fmtTime(pattern.created_at)}</span>
      </div>
    </div>
  </article>;
}

function Pagination({ page, pages, total, setOffset }: { page: number; pages: number; total: number; setOffset: (offset: number) => void }) {
  if (total === 0) return null;
  return <div className="pagination">
    <span className="muted">共 {total} 条 · 第 {page}/{pages} 页</span>
    <button className="btn" disabled={page <= 1} onClick={() => setOffset((page - 2) * PAGE_SIZE)}>上一页</button>
    <button className="btn" disabled={page >= pages} onClick={() => setOffset(page * PAGE_SIZE)}>下一页</button>
  </div>;
}
