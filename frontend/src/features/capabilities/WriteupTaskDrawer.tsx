import { useState, type ReactNode } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Badge, EmptyState } from '../../components/ui';
import { useToast } from '../../components/Toast';
import { ConfirmModal, type ConfirmRequest } from '../../components/ConfirmModal';
import {
  cancelTask, extractProducts, fetchProducts, fetchReport, fetchTask, generateReport, generateSpec,
  rerunTask, runTask, stopTask,
} from './writeupReproQueries';
import type {
  EvidenceCommand, RecipeJson, RecipeStep, WriteupPatternRow, WriteupRecipeRow, WriteupReport, WriteupTask,
} from './writeupReproTypes';
import {
  failureLabel, fmtDuration, fmtTime, matchedMeta, sideLabel, statusMeta, triggerLabel, verdictMeta,
} from './writeupReproLabels';

/**
 * 一条复现任务的详情抽屉。
 *
 * 六个 tab 的顺序是**读的顺序**: 概览(这是什么、跑到哪了) → 报告(八节结论) →
 * 证据(命令原文) → spec(打算怎么跑) → 产物(固化下来的 recipe/pattern) → 日志(原样)。
 *
 * 一条规矩贯穿全部: **页面上出现的每个结论都要能点回到它的证据**。报告第 3 节与 recipe 的
 * 每一步都带 `index`, 而这个 index 就是证据包里的命令序号 —— 所以三处渲染共用
 * `EvidenceCommand` 的形状, 不做"摘要版"。
 */

type Tab = 'overview' | 'report' | 'evidence' | 'spec' | 'products' | 'log';

const TAB_LABELS: Array<[Tab, string]> = [
  ['overview', '概览'],
  ['report', '报告'],
  ['evidence', '证据'],
  ['spec', 'spec'],
  ['products', '产物'],
  ['log', '日志'],
];

const ACTIVE_STATUSES = ['pending', 'spec_ready', 'queued', 'running'];

export function WriteupTaskDrawer({ taskId }: { taskId: number }) {
  const [tab, setTab] = useState<Tab>('overview');
  const taskQuery = useQuery({
    queryKey: ['writeup', 'task', taskId],
    queryFn: () => fetchTask(taskId),
    // 跑着的时候 5s 一次(证据是边跑边落库的), 终结之后不再轮询 —— 抽屉开着也不该一直打库。
    refetchInterval: query => (ACTIVE_STATUSES.includes((query.state.data as WriteupTask | undefined)?.status ?? '') ? 5_000 : false),
  });
  const task = taskQuery.data;
  if (!task) {
    return taskQuery.isError
      ? <EmptyState title="读不到这条任务" description={errorText(taskQuery.error, '任务接口报错')} />
      : <EmptyState title="正在加载任务…" />;
  }

  const counts: Record<Tab, number> = {
    overview: 0,
    report: task.products?.report ? 1 : 0,
    evidence: task.evidence_json?.section?.commands?.length ?? 0,
    spec: task.spec_json?.steps?.length ?? 0,
    products: (task.products?.recipe ? 1 : 0) + (task.products?.pattern ? 1 : 0),
    log: 0,
  };

  return <div className="v11-view">
    <TaskActions task={task} />
    <div className="viewbar case-tabs" style={{ marginTop: 10 }}>
      {TAB_LABELS.map(([id, label]) => <button
        key={id}
        className={`view-pill ${tab === id ? 'active' : ''}`}
        onClick={() => setTab(id)}
      >{label}{counts[id] ? ` ${counts[id]}` : ''}</button>)}
    </div>
    {tab === 'overview' && <OverviewTab task={task} />}
    {tab === 'report' && <ReportTab task={task} />}
    {tab === 'evidence' && <EvidenceTab task={task} />}
    {tab === 'spec' && <SpecTab task={task} />}
    {tab === 'products' && <ProductsTab task={task} />}
    {tab === 'log' && <LogTab task={task} />}
  </div>;
}

// ========== 动作条 ==========

/**
 * 动作按**状态**给, 不给一套按钮让用户自己撞 400:
 * 未结束 → 生成 spec / 开跑 / 停止 / 取消; 终态 → 重跑 / 生成报告 / 抽产物。
 * 重跑是**新开一行**, 所以它带二次确认 —— 它不是"把结论翻过来"。
 */
function TaskActions({ task }: { task: WriteupTask }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState<ConfirmRequest | null>(null);
  const active = ACTIVE_STATUSES.includes(task.status);
  const terminal = !active;
  const hasSteps = (task.spec_json?.steps?.length ?? 0) > 0;
  const hasReport = Boolean(task.products?.report);

  const refresh = () => {
    void qc.invalidateQueries({ queryKey: ['writeup'] });
  };
  const onError = (error: unknown) => toast(errorText(error, '操作失败'), 'error');

  const spec = useMutation({
    mutationFn: () => generateSpec(task.id),
    onSuccess: () => { toast('spec 已生成并通过校验', 'success'); refresh(); },
    onError,
  });
  const run = useMutation({
    mutationFn: () => runTask(task.id),
    onSuccess: result => { toast(result.started ? '已开跑（后台线程，约几分钟）' : result.reason || '已有线程在跑', result.started ? 'success' : 'info'); refresh(); },
    onError,
  });
  const stop = useMutation({
    mutationFn: () => stopTask(task.id),
    onSuccess: result => { toast(result.signalled ? '已发出停止信号，线程会在下一个心跳点退出' : '这条任务没有在跑的线程', 'info'); refresh(); },
    onError,
  });
  const cancel = useMutation({
    mutationFn: () => cancelTask(task.id),
    onSuccess: () => { toast('已取消', 'success'); refresh(); },
    onError,
  });
  const rerun = useMutation({
    mutationFn: () => rerunTask(task.id),
    onSuccess: result => { toast(`已新开第 ${result.task.attempt} 遍（上一遍的记录原样保留）`, 'success'); refresh(); },
    onError,
  });
  const report = useMutation({
    mutationFn: () => generateReport(task.id),
    onSuccess: () => { toast('报告已生成', 'success'); refresh(); },
    onError,
  });
  const extract = useMutation({
    mutationFn: () => extractProducts(task.id),
    onSuccess: result => {
      toast(result.status === 'ok'
        ? '已从报告抽出配方 / 规律'
        : `没抽出产物：${(result.reasons ?? []).join('；') || '结论不支持'}`, result.status === 'ok' ? 'success' : 'info');
      refresh();
    },
    onError,
  });

  const busy = spec.isPending || run.isPending || stop.isPending || cancel.isPending
    || rerun.isPending || report.isPending || extract.isPending;

  return <div className="viewbar">
    {active && task.status !== 'running' && task.status !== 'queued' && !hasSteps && <button className="btn primary" disabled={busy} onClick={() => spec.mutate()}>{spec.isPending ? '生成中…' : '生成 spec'}</button>}
    {active && hasSteps && <button className="btn primary" disabled={busy || task.status === 'running'} onClick={() => run.mutate()}>{run.isPending ? '启动中…' : '开跑'}</button>}
    {task.status === 'running' && <button className="btn" disabled={busy} onClick={() => setConfirm({
      title: '停止这次执行？',
      message: <p>只会置一个停止标志，线程在下一个心跳点退出并落 <b>cancelled</b>（没有结论）。已经落库的证据保留。</p>,
      confirmLabel: '停止',
      onConfirm: () => stop.mutate(),
    })}>停止</button>}
    {active && <button className="btn" disabled={busy} onClick={() => setConfirm({
      title: '取消这条任务？',
      message: <p>取消后任务落 <b>cancelled</b>，没有结论。想再跑要重开一行（重跑）。</p>,
      confirmLabel: '取消任务',
      onConfirm: () => cancel.mutate(),
    })}>取消</button>}
    {terminal && <button className="btn" disabled={busy} onClick={() => setConfirm({
      title: `重跑第 ${task.attempt + 1} 遍？`,
      message: <p>
        重跑会<b>新开一行</b>（attempt+1），带着这一遍的 spec 再执行一次。
        这一行（含证据与结论）原样保留 —— 重跑不是"把上一遍的结论翻过来"，而是再要一次独立执行。
      </p>,
      confirmLabel: '重跑',
      onConfirm: () => rerun.mutate(),
    })}>重跑</button>}
    {terminal && <button className="btn" disabled={busy} onClick={() => report.mutate()}>{report.isPending ? '生成中…' : hasReport ? '重生成报告' : '生成报告'}</button>}
    {hasReport && <button className="btn" disabled={busy} onClick={() => extract.mutate()}>{extract.isPending ? '抽取中…' : '重抽产物'}</button>}
    <ConfirmModal request={confirm} onClose={() => setConfirm(null)} />
  </div>;
}

// ========== 概览 ==========

function OverviewTab({ task }: { task: WriteupTask }) {
  const status = statusMeta(task.status);
  const verdict = task.verdict ? verdictMeta(task.verdict) : null;
  return <>
    <Section title="这条任务" note={`#${task.id} · 第 ${task.attempt} 遍 · ${triggerLabel(task.trigger)}`}>
      <div className="badges">
        <Badge tone={status.tone}>{status.label}</Badge>
        {verdict && <Badge tone={verdict.tone}>{verdict.label}</Badge>}
        {task.failure_reason && <Badge tone="slate">{failureLabel(task.failure_reason)}</Badge>}
        <Badge tone="slate">素材 #{task.material_id}</Badge>
      </div>
      {status.hint && <p className="muted small" style={{ margin: '8px 0 0' }}>{status.hint}</p>}
      <Row label="文章声称" value={task.claim ? `「${task.claim}」` : ''} />
      <Row label="原文引句" value={task.claim_quote ? <Quote text={task.claim_quote} /> : ''} />
      <Row label="目标" value={[task.target_repo, task.target_version, task.target_kind].filter(Boolean).join(' · ')} />
      <Row label="来源文章" value={task.material
        ? (task.material.url
          ? <a href={task.material.url} target="_blank" rel="noreferrer">{task.material.title || task.material.url}</a>
          : task.material.title || `素材 #${task.material_id}`)
        : <span className="muted">素材 #{task.material_id} 已查不到（可能被清理）</span>} />
      <Row label="发起" value={`${triggerLabel(task.trigger)} · ${task.created_by || '未知'} · ${fmtTime(task.created_at)}`} />
      <Row label="耗时 / 工具调用" value={`${fmtDuration(task.duration_seconds)} · ${task.tool_calls ?? '—'} 次`} />
      <Row label="spec 来源" value={task.spec_source === 'human' ? '人工编写' : task.spec_source === 'llm' ? `模型生成（试了 ${task.spec_attempts} 次）` : '还没有 spec'} />
      <Row label="容器 / 会话" value={[task.container_name, task.session_id].filter(Boolean).join(' · ')} />
      {task.review_verdict && <Row label="复核" value={`${task.review_verdict}${task.review_reason ? ` · ${task.review_reason}` : ''}`} />}
      {task.failure_reason && <Row label="失败原因" value={failureLabel(task.failure_reason)} />}
    </Section>
  </>;
}

// ========== 报告(八节) ==========

/**
 * 八节**逐节渲染, 缺一节就写"这一节没有内容"** —— 后端在模型报错时宁可不落库,
 * 所以"有一份报告"就意味着第 1-4 节一定来自规则(页面上能看出哪几节是模型写的)。
 */
function ReportTab({ task }: { task: WriteupTask }) {
  const reportQuery = useQuery({
    queryKey: ['writeup', 'report', task.id],
    queryFn: () => fetchReport(task.id),
    staleTime: 60_000,
  });
  if (reportQuery.isLoading) return <EmptyState title="正在读取报告…" />;
  if (reportQuery.isError) return <EmptyState title="报告读取失败" description={errorText(reportQuery.error, '报告接口报错')} />;
  const report = reportQuery.data;
  if (!report) {
    return <EmptyState
      title="这条任务还没有复现报告"
      description={ACTIVE_STATUSES.includes(task.status)
        ? '报告在任务终结时由执行器自动生成。现在还跑着（或还没跑），所以没有报告是正常的 —— 不是丢了。'
        : '任务已终结但报告不存在。T4.3 之前跑完的任务没有报告，点上面的「生成报告」补一份；模型网关故障时也会是空的，可重试。'}
    />;
  }
  return <ReportBody report={report} />;
}

function ReportBody({ report }: { report: WriteupReport }) {
  const verdict = verdictMeta(report.verdict);
  const claim = report.claim_json ?? {};
  const observed = report.observed_json ?? {};
  const attribution = report.attribution_json ?? {};
  const root = report.root_cause_json ?? {};
  const pattern = report.pattern_json ?? {};
  const commands = report.evidence_json?.section?.commands ?? [];
  const generation = report.evidence_json?.generation;
  const matched = matchedMeta(observed.matched);

  return <>
    <Section no="①" title="结论" note={`报告生成于 ${fmtTime(report.created_at)}`}>
      <div className="badges">
        <Badge tone={verdict.tone}>{verdict.label}</Badge>
        {report.failure_reason && <Badge tone="slate">{failureLabel(report.failure_reason)}</Badge>}
        <Badge tone="slate">{report.generated_by === 'hybrid' ? '规则 + 模型' : report.generated_by === 'llm' ? '模型' : '规则'}</Badge>
      </div>
      {report.reviewed_by && <Row label="复核" value={`${report.reviewed_by} · ${fmtTime(report.reviewed_at)}`} />}
    </Section>

    <Section no="②" title="文章声称什么" note={`${claim.speaker === 'author' ? '作者' : '原文'} · 第 2 节`}>
      <Row label="声称" value={claim.claim} />
      <Row label="引句" value={claim.claim_quote ? <Quote text={claim.claim_quote} /> : ''} />
      <Row label="声称的效果" value={claim.claimed_effect} />
      <Row label="目标" value={[claim.target?.repo, claim.target?.version, claim.target_product, claim.target_cve].filter(Boolean).join(' · ')} />
      <Row label="PoC 语言 / 环境" value={[claim.poc_lang, claim.env_hint].filter(Boolean).join(' · ')} />
      <Row label="原文来源" value={claim.source?.url
        ? <a href={claim.source.url} target="_blank" rel="noreferrer">{claim.source.title || claim.source.url}</a>
        : claim.source?.title ?? ''} />
    </Section>

    <Section no="③" title="实际执行了什么" note={`${commands.length} 条命令 · 只读 transcript，不读 agent 自述`}>
      {commands.length === 0
        ? <p className="muted small">这一节没有命令 —— 执行没跑起来。</p>
        : <div>{commands.map(command => <CommandBlock key={`${command.index}-${command.cmd}`} command={command} />)}</div>}
      {report.evidence_json?.section?.duration_seconds != null && <p className="muted small" style={{ marginTop: 8 }}>
        执行 {fmtDuration(report.evidence_json.section.duration_seconds)} · {report.evidence_json.section.tool_calls ?? '—'} 次工具调用
      </p>}
    </Section>

    <Section no="④" title="实测现象" note="平台拿真实退出码与完整 stdout 重算，不信 agent 报的命中">
      <div className="badges"><Badge tone={matched.tone}>{matched.text}</Badge>
        {observed.probe_found === false && <span className="muted small">没在 transcript 里找到 probe 命令</span>}
      </div>
      <Row label="判据" value={observed.success_signal} />
      <Row label="probe 命令" value={observed.cmd ? <code>{observed.cmd}</code> : ''} />
      <Row label="退出码" value={observed.exit_code == null
        ? (observed.exit_code_source === 'unknown' ? '不可知（判定来自 stdout 匹配，不是退出码）' : '—')
        : `${observed.exit_code}（${observed.exit_code_source === 'printed' ? '从输出里读回' : observed.exit_code_source === 'shell' ? 'shell 退出码' : observed.exit_code_source || '来源未知'}）`} />
      <Row label="出现次数" value={observed.occurrences ? `${observed.occurrences} 次` : ''} />
      <Row label="为什么" value={observed.why} />
      <Row label="期望效果" value={observed.expected_effect} />
      {observed.stdout_tail ? <pre className="snippet case-code">{observed.stdout_tail}</pre> : null}
      {(observed.evidence_gaps ?? []).length > 0 && <Row label="证据缺口" value={(observed.evidence_gaps ?? []).join('；')} />}
      {observed.agent_self_report && Object.keys(observed.agent_self_report).length > 0 && <details style={{ marginTop: 8 }}>
        <summary className="small muted" style={{ cursor: 'pointer' }}>agent 自述（只作对照，不作判据）</summary>
        <pre className="snippet case-code">{JSON.stringify(observed.agent_self_report, null, 2)}</pre>
      </details>}
    </Section>

    <Section no="⑤" title="归因" note="不能与结论冲突：模型的说法与平台判定不一致时两条都留">
      <Row label="方向" value={sideLabel(attribution.side)} />
      <Row label="理由" value={attribution.reason} />
      {attribution.model_side && attribution.model_side !== attribution.side && <Row label="模型的说法" value={`${sideLabel(attribution.model_side)}${attribution.model_reason ? ` · ${attribution.model_reason}` : ''}`} />}
      {(attribution.evidence_refs ?? []).length > 0 && <Row label="指向" value={`第 3 节命令 ${(attribution.evidence_refs ?? []).map(ref => `#${ref}`).join(', ')}`} />}
    </Section>

    <Section no="⑥" title="漏洞根因" note={root.provenance === 'from_article' ? '位置已在原文中对上' : root.provenance ? '位置未完全对上，已降级但内容保留' : ''}>
      <Row label="位置" value={[root.location?.file, root.location?.function, root.location?.lines].filter(Boolean).join(' · ')} />
      <Row label="被破坏的不变量" value={root.invariant} />
      <Row label="破坏方式" value={root.broken_by} />
      <Row label="前置条件" value={(root.preconditions ?? []).join('；')} />
      {root.code_quote ? <pre className="snippet case-code">{root.code_quote}</pre> : null}
      <Row label="校验" value={root.checked_against} />
      {root.provenance && <div className="badges" style={{ marginTop: 8 }}>
        <Badge tone={root.provenance === 'from_article' ? 'green' : root.provenance === 'llm_extracted_unverified' ? 'red' : 'amber'}>
          {root.provenance === 'from_article' ? '原文可溯源' : root.provenance === 'llm_extracted_unverified' ? '模型推断·未对上' : '模型推断'}
        </Badge>
      </div>}
    </Section>

    <Section no="⑦" title="发现规律" note={pattern.verified ? '已通过入库闸门' : '未通过闸门，不进规律库'}>
      <Row label="不变量" value={pattern.invariant} />
      <Row label="代码特征" value={pattern.code_feature} />
      <Row label="审计入口" value={pattern.audit_entry} />
      <Row label="判别点" value={pattern.discriminator} />
      <Row label="泛化边界" value={pattern.generalization} />
      <Row label="置信度" value={pattern.confidence != null ? `${Math.round(Number(pattern.confidence) * 100)}%` : ''} />
      <div className="badges" style={{ marginTop: 8 }}>
        <Badge tone={pattern.verified ? 'green' : 'amber'}>{pattern.verified ? '第 7 节通过校验' : '第 7 节未通过校验'}</Badge>
        {pattern.provenance && <Badge tone="slate">{pattern.provenance}</Badge>}
      </div>
      {(pattern.blockers ?? []).length > 0 && <Row label="卡在哪" value={(pattern.blockers ?? []).join('；')} />}
    </Section>

    <Section no="⑧" title="限制与存疑" note={`${report.caveats.length} 条`}>
      <ul className="small" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8 }}>
        {report.caveats.map((item, index) => <li key={`${index}-${item.slice(0, 12)}`}>{item}</li>)}
      </ul>
      {generation && <p className="muted small" style={{ margin: '10px 0 0' }}>
        生成信息：{generation.model || generation.provider || '—'} · {generation.prompt_chars ?? '—'} 字提示词 ·
        根因{generation.root_cause_verified ? '已校验' : '未校验'} · 规律{generation.pattern_verified ? '已校验' : '未校验'}
      </p>}
    </Section>
  </>;
}

// ========== 证据 ==========

function EvidenceTab({ task }: { task: WriteupTask }) {
  const reportQuery = useQuery({
    queryKey: ['writeup', 'report', task.id],
    queryFn: () => fetchReport(task.id),
    staleTime: 60_000,
  });
  // 报告里带了证据包(第 3 节 + pack)。没有报告时退回任务行上的 evidence_json ——
  // 老任务(报告没生成)也仍然有证据可看, 那是它们唯一的事实来源。
  const evidence = reportQuery.data?.evidence_json ?? task.evidence_json ?? {};
  const section = evidence.section;
  const commands = section?.commands ?? evidence.pack?.commands ?? [];
  const probe = evidence.pack?.probe;
  const pack = evidence.pack;

  return <>
    <Section title="执行记录" note={section ? `平台摘录 ${commands.length} 条` : '来自任务行上落库的证据包'}>
      {commands.length === 0
        ? <p className="muted small">没有命令记录 —— 这条任务没跑到执行那一步（或证据包不完整）。</p>
        : <div>{commands.map(command => <CommandBlock key={`${command.index}-${command.cmd}`} command={command} />)}</div>}
    </Section>

    {probe && <Section title="probe 重算" note="退出码与 stdout 都由平台重算">
      <Row label="probe 命令" value={probe.cmd ? <code>{probe.cmd}</code> : ''} />
      <Row label="spec 里的命令" value={probe.spec_cmd ? <code>{probe.spec_cmd}</code> : ''} />
      <Row label="命中" value={matchedMeta(probe.matched).text} />
      <Row label="退出码" value={probe.exit_code == null ? '不可知' : String(probe.exit_code)} />
      <Row label="外层 shell 退出码" value={probe.shell_exit_code == null ? '' : String(probe.shell_exit_code)} />
      <Row label="退出码来源" value={probe.exit_code_source} />
      <Row label="出现次数" value={probe.occurrences ? String(probe.occurrences) : ''} />
      <Row label="判据" value={probe.success_signal} />
      <Row label="为什么" value={probe.why} />
    </Section>}

    {pack && <Section title="证据包" note={pack.collected_at ? `采集于 ${fmtTime(pack.collected_at)}` : ''}>
      <Row label="版本" value={pack.version != null ? `v${pack.version}` : ''} />
      <Row label="耗时 / 工具调用" value={`${fmtDuration(pack.duration_seconds)} · ${pack.tool_calls ?? '—'}`} />
      {pack.incomplete && <Row label="完整性" value={`不完整：${(pack.incomplete_reasons ?? []).join('；') || '有缺口'}`} />}
      {pack.guard && <Row label="安全边界" value={JSON.stringify(pack.guard)} />}
      {pack.egress && <Row label="出网审计" value={JSON.stringify(pack.egress)} />}
    </Section>}
  </>;
}

// ========== spec ==========

function SpecTab({ task }: { task: WriteupTask }) {
  const spec = task.spec_json ?? {};
  const steps = spec.steps ?? [];
  if (steps.length === 0) {
    return <EmptyState
      title="还没有可执行的 spec"
      description="spec 是「怎么算复现成功」的可执行形态：目标、步骤、probe、判据。它由模型按原文生成并逐条回原文校验，点上面的「生成 spec」开始。"
    />;
  }
  return <>
    <Section title="目标" note={spec.verification?.strict ? '严格校验' : '放宽校验（人工 spec 不拿 substring 否掉人）'}>
      <Row label="仓库" value={spec.target?.repo} />
      <Row label="版本" value={spec.target?.ref} />
      <Row label="类型" value={spec.target?.kind} />
      {(spec.target?.setup ?? []).length > 0 && <Row label="准备命令" value={<pre className="snippet case-code">{(spec.target?.setup ?? []).join('\n')}</pre>} />}
      <Row label="声称" value={spec.claim} />
      <Row label="引句" value={spec.claim_quote ? <Quote text={spec.claim_quote} /> : ''} />
    </Section>

    <Section title="步骤" note={`${steps.length} 步 · 每步都能回指报告第 3 节`}>
      {steps.map((step, index) => <div className="case-context-row" key={`${index}-${step.run.slice(0, 12)}`}>
        <div className="badges">
          <Badge tone="sky">步骤 {index + 1}</Badge>
          {step.index != null && <Badge tone="slate">证据 #{step.index}</Badge>}
        </div>
        <pre className="snippet case-code">{step.run}</pre>
        {step.expect && <p className="small" style={{ margin: '6px 0 0' }}><span className="muted">期望</span> {step.expect}</p>}
        {step.source_quote && <Quote text={step.source_quote} />}
      </div>)}
    </Section>

    <Section title="probe 与判据" note="判据由平台重算，agent 自报的命中一律丢弃">
      <Row label="类型" value={spec.probe?.type} />
      <Row label="命令" value={spec.probe?.cmd ? <code>{spec.probe.cmd}</code> : ''} />
      <Row label="判据" value={spec.probe?.success_signal} />
      <Row label="校验" value={[
        spec.verification?.strict ? '严格模式' : '放宽模式',
        spec.verification?.claim_quote_checked ? '引句已核对' : '引句未核对',
        spec.verification?.steps_checked != null ? `核对了 ${spec.verification.steps_checked} 步` : '',
      ].filter(Boolean).join(' · ')} />
      {(spec.verification?.notes ?? []).length > 0 && <Row label="校验备注" value={(spec.verification?.notes ?? []).join('；')} />}
      {(spec.verification_notes ?? []).length > 0 && <Row label="备注" value={(spec.verification_notes ?? []).join('；')} />}
    </Section>
  </>;
}

// ========== 产物 ==========

function ProductsTab({ task }: { task: WriteupTask }) {
  const productsQuery = useQuery({
    queryKey: ['writeup', 'products', task.id],
    queryFn: () => fetchProducts(task.id),
    staleTime: 60_000,
  });
  if (productsQuery.isLoading) return <EmptyState title="正在读取产物…" />;
  const recipe = productsQuery.data?.recipe ?? null;
  const pattern = productsQuery.data?.pattern ?? null;
  if (!recipe && !pattern) {
    return <EmptyState
      title="这条任务没有可复用的产物"
      description={ACTIVE_STATUSES.includes(task.status)
        ? '产物在任务终结时从报告里抽：recipe 只从 success / partial 抽，pattern 要求第 7 节通过校验。'
        : '没抽出来是结论本身决定的：failed / blocked 没有可复用的执行路径；第 7 节没通过校验也不会入库。老任务（T4.3 之前跑完的）需要先补一份报告再抽。'}
    />;
  }
  return <>
    {recipe && <RecipeCard recipe={recipe} />}
    {pattern && <PatternCard pattern={pattern} />}
  </>;
}

function RecipeCard({ recipe }: { recipe: WriteupRecipeRow }) {
  const body: RecipeJson = recipe.recipe_json ?? {};
  const groups: Array<[string, RecipeStep[], string]> = [
    ['取得目标', body.acquire ?? [], 'clone / 下载制品'],
    ['准备环境', body.setup ?? [], '装依赖、建虚拟环境、编译'],
    ['触发', body.trigger ?? [], '真正跑 PoC'],
  ];
  return <Section title="配方（这一类怎么跑）" note={`${recipe.recipe_key}${recipe.degraded ? ' · 降级（来自 partial）' : ''}`}>
    {recipe.degraded && <p className="muted small" style={{ marginTop: 0 }}>
      这份配方来自一次 <b>partial</b>（只做到一半）的执行 —— 路径是跑过的，但不要当成"这条一定成功"。
    </p>}
    <Row label="指纹" value={(body.applies_to?.fingerprint ?? recipe.fingerprint_json ?? []).join(' · ')} />
    <Row label="来源" value={`任务 #${recipe.task_id} · 材料 #${recipe.material_id} · ${body.source?.verdict ?? ''}`} />
    {groups.map(([title, steps, hint]) => steps.length === 0 ? null : <div key={title} style={{ marginTop: 12 }}>
      <p className="small" style={{ margin: '0 0 6px' }}><b>{title}</b> <span className="muted">· {hint}</span></p>
      {steps.map((step, index) => <CommandBlock
        key={`${title}-${index}`}
        command={{ index: step.index ?? undefined, cmd: step.cmd, exit_code: step.exit_code ?? undefined }}
      />)}
    </div>)}
    {body.probe && <div style={{ marginTop: 12 }}>
      <p className="small" style={{ margin: '0 0 6px' }}><b>probe</b> <span className="muted">· 判定用的那条</span></p>
      <CommandBlock command={{ index: body.probe.index ?? undefined, cmd: body.probe.cmd ?? '', exit_code: body.probe.exit_code ?? undefined }} />
      <Row label="判据" value={body.probe.success_signal} />
      <Row label="退出码来源" value={body.probe.exit_code_source} />
      <Row label="出现次数" value={body.probe.occurrences ? String(body.probe.occurrences) : ''} />
    </div>}
    {(body.known_pitfalls ?? []).length > 0 && <div style={{ marginTop: 12 }}>
      <p className="small" style={{ margin: 0 }}><b>已知坑</b></p>
      <ul className="small muted" style={{ margin: '4px 0 0', paddingLeft: 18, lineHeight: 1.8 }}>
        {(body.known_pitfalls ?? []).map((item, index) => <li key={index}>{item}</li>)}
      </ul>
    </div>}
    {(body.omitted ?? []).length > 0 && <p className="muted small" style={{ marginTop: 10 }}>
      有 {body.omitted?.length} 条命令没进配方（导航/巡检类），原因记在报告的 omission 里。
    </p>}
    {body.truncated ? <p className="muted small">命令超过上限，配方被截断（原文里有 truncated 字段）。</p> : null}
  </Section>;
}

function PatternCard({ pattern }: { pattern: WriteupPatternRow }) {
  return <Section title="规律（这一类怎么找）" note={`#${pattern.id} · ${pattern.generalization}`}>
    <Row label="不变量" value={pattern.invariant} />
    <Row label="代码特征" value={pattern.code_feature} />
    <Row label="审计入口" value={pattern.audit_entry} />
    <Row label="判别点" value={pattern.discriminator} />
    <Row label="来源" value={`任务 #${pattern.report_id} · 材料 #${pattern.material_id} · ${pattern.provenance}`} />
    <Row label="置信度" value={pattern.confidence != null ? `${Math.round(pattern.confidence * 100)}%` : ''} />
    <Row label="指纹" value={(pattern.fingerprint ?? []).join(' · ')} />
  </Section>;
}

// ========== 日志 ==========

function LogTab({ task }: { task: WriteupTask }) {
  if (!task.log) return <EmptyState title="没有日志" description="执行器把会话输出落在这里；没跑到执行那一步就是空的（不是被截断）。" />;
  return <Section title="原始日志" note={`${task.log.length} 字`}>
    <pre className="snippet case-code" style={{ maxHeight: 560 }}>{task.log}</pre>
  </Section>;
}

// ========== 小组件 ==========

function Section({ no, title, note, children }: { no?: string; title: string; note?: string; children: ReactNode }) {
  return <section className="panel" style={{ marginTop: 10 }}>
    <div className="panel-head"><h3>{no ? `${no} ${title}` : title}</h3>{note && <span>{note}</span>}</div>
    <div className="panel-body">{children}</div>
  </section>;
}

/** 一行"标签 + 值"。**空值不渲染** —— 一排"未知 / —"会把真正有内容的那几行淹掉。 */
function Row({ label, value }: { label: string; value: ReactNode }) {
  if (value == null || value === '' || value === false) return null;
  if (Array.isArray(value) && value.length === 0) return null;
  return <p className="small" style={{ margin: '7px 0 0' }}>
    <span className="muted">{label}</span>{' '}{value}
  </p>;
}

/** 原文引句。左竖线而不是引号块 —— 引用里常有代码, 引号会和代码里的引号打架。 */
function Quote({ text }: { text: string }) {
  return <span style={{
    display: 'block', margin: '4px 0 0', paddingLeft: 10,
    borderLeft: '2px solid var(--line-strong)', color: 'var(--muted)',
  }}>{text}</span>;
}

/** 一条命令 + 它的退出码与输出尾部。报告第 3 节、证据 tab、recipe 三处共用同一个形状。 */
export function CommandBlock({ command }: { command: EvidenceCommand }) {
  const code = command.exit_code;
  return <div className="case-context-row">
    <div className="badges">
      {command.index != null && <Badge tone="slate">#{command.index}</Badge>}
      <Badge tone={code == null ? 'slate' : code === 0 ? 'green' : 'amber'}>退出码 {code == null ? '—' : code}</Badge>
      {command.completed === false && <Badge tone="amber">未跑完</Badge>}
      {command.stdout_chars ? <span className="muted small">{command.stdout_chars} 字输出</span> : null}
    </div>
    <pre className="snippet case-code">{command.cmd}</pre>
    {command.stdout_tail ? <pre className="snippet case-code">{command.stdout_tail}</pre> : null}
    {command.stdout_sha1 && <p className="muted small" style={{ margin: '6px 0 0' }}>stdout sha1 {String(command.stdout_sha1).slice(0, 12)}</p>}
  </div>;
}

/**
 * 后端的错误只带状态码(`client.ts` 抛 `path: status`)。这里补一句人能看懂的话 ——
 * 这几种状态码在 writeup 复现里有确定含义, 不该让用户自己去翻接口文档。
 */
function errorText(error: unknown, fallback: string): string {
  const message = (error as Error)?.message ?? String(error);
  if (message.endsWith(': 502')) return '模型没给出能对上原文的结果；本次已丢弃，可重试';
  if (message.endsWith(': 503')) return '模型网关不可用，本次没有写入任何结论，可稍后重试';
  if (message.endsWith(': 404')) return '报告还没生成';
  if (message.endsWith(': 400')) return '当前状态不允许这个操作（刷新后再看）';
  return `${fallback}（${message}）`;
}
