import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Badge, Card, EmptyState } from '../../components/ui';
import { useToast } from '../../components/Toast';
import { addCaseContext, fetchCaseDetail, fetchPatternCases, fetchVulnerabilityMaterial, updateCase } from '../../api/vulnerabilities';
import type { CaseContextRow, CaseContextType, CasePayload, CaseDetail, CasePatternLink } from '../../types/vulnerability';
import type { DomainItem, MaterialPayload } from '../../types/vulnerability';

/** 与 VulnerabilityPage 里的 DrawerState 结构一致(那边没导出, 这里按结构对齐即可)。 */
export type DrawerSetter = (drawer: { title: string; subtitle?: string; body: JSX.Element } | null) => void;

/**
 * 漏洞案例详情。**入口只传 id 与标题**(列表里已经有这两个), 上下文由本组件自己拉 ——
 * 列表接口刻意不带 content(代码片段只在详情里出现), 所以这里必然是第二次请求。
 */
export function openCaseDrawer(
  item: Pick<CasePayload, 'id' | 'title' | 'canonical_id' | 'id_kind'>,
  setDrawer: DrawerSetter,
  onOpenMaterial?: (itemId: number) => void,
  onOpenPattern?: (itemId: number) => void,
) {
  setDrawer({
    title: item.title || item.canonical_id,
    subtitle: `${item.canonical_id} · 正在加载上下文…`,
    body: <CaseDetailPanel caseId={item.id} onOpenMaterial={onOpenMaterial} onOpenPattern={onOpenPattern} />,
  });
}

const STATUS_LABELS: Record<string, string> = {
  pending_fetch: '待抓元数据',
  draft: '草稿',
  active: '已入库',
  superseded: '已取代',
};

/**
 * 上下文来源标签。这是"事实 vs 推断"的**唯一视觉分层**:
 * 外部源/补丁 = 事实(绿), 继承素材 = 站内既有证据(蓝), 模型抽取 = 推断(琥珀, 还要带置信度),
 * 人写的 = 人工(violet)。三者混在一张表里却长得一样, 用户就没法判断该信谁。
 */
function provenanceBadge(provenance: string, confidence?: number | null) {
  const label = ({
    from_nvd: 'NVD 事实',
    from_osv: 'OSV 事实',
    from_patch: '补丁事实',
    from_source: '源码事实',
    from_legacy_event: '继承素材',
    from_material_cve: '文章提及',
    llm_extracted: '模型推断',
    llm_extracted_unverified: '模型推断·未校验',
    manual_added: '人工补充',
  } as Record<string, string>)[provenance] ?? provenance;
  const tone = provenance === 'manual_added' ? 'violet'
    : provenance === 'llm_extracted' ? 'amber'
    : provenance === 'llm_extracted_unverified' ? 'red'
    : provenance === 'from_legacy_event' || provenance === 'from_material_cve' ? 'sky' : 'green';
  return <Badge tone={tone}>{label}{confidence != null && provenance.startsWith('llm_extracted') ? ` ${Math.round(confidence * 100)}%` : ''}</Badge>;
}

const CONTEXT_LABELS: Record<CaseContextType, string> = {
  patch_diff: '补丁 diff',
  vuln_site: '漏洞点',
  dataflow: '数据流',
  caller_snippet: '调用方代码',
  reference: '引用 / 素材',
  manual_note: '人工说明',
};

/** 4 格完整度指示器: 元数据 / 补丁 / 漏洞点 / 数据流 —— 把"上下文收全了没有"放到列表上。 */
export function ContextDots({ item }: { item: CasePayload }) {
  const bits: Array<[string, number, string]> = [
    ['元', item.metadata_complete, '元数据(标题 + 严重性/CVSS)'],
    ['补', item.has_patch, '补丁 diff'],
    ['点', item.has_vuln_site, '漏洞点(文件/函数/行号)'],
    ['流', item.has_dataflow, '数据流(source → sink)'],
  ];
  return <div className="context-dots">{bits.map(([label, on, title]) => <span key={label} className={`context-dot ${on ? 'on' : ''}`} title={`${title}:${on ? '已有' : '缺失'}`}>{label}</span>)}</div>;
}

function CaseDetailPanel({ caseId, onOpenMaterial, onOpenPattern }: { caseId: number; onOpenMaterial?: (itemId: number) => void; onOpenPattern?: (itemId: number) => void }) {
  const [tab, setTab] = useState<'overview' | CaseContextType>('overview');
  const detail = useQuery({ queryKey: ['vulnerabilities', 'case', caseId], queryFn: () => fetchCaseDetail(caseId) });
  if (detail.isLoading) return <EmptyState title="正在加载案例上下文…" />;
  if (detail.isError || !detail.data) return <EmptyState title="案例详情加载失败" description={String(detail.error ?? '未知错误')} />;
  const item = detail.data;
  const context = item.context ?? {};
  const tabs: Array<['overview' | CaseContextType, string, number]> = [
    ['overview', '概览', 0],
    ['patch_diff', '补丁', (context.patch_diff ?? []).length],
    ['vuln_site', '漏洞点', (context.vuln_site ?? []).length],
    ['dataflow', '数据流', (context.dataflow ?? []).length],
    ['caller_snippet', '调用方', (context.caller_snippet ?? []).length],
    ['reference', '引用 / 素材', (context.reference ?? []).length],
    ['manual_note', '人工说明', (context.manual_note ?? []).length],
  ];
  return <div className="grid drawer-detail">
    <Card>
      <div className="badges">
        <Badge tone="red">{item.canonical_id}</Badge>
        <Badge tone={item.status === 'active' ? 'green' : 'amber'}>{STATUS_LABELS[item.status] ?? item.status}</Badge>
        {item.severity && <Badge tone={severityTone(item.severity)}>{item.severity}{item.cvss_score != null ? ` ${item.cvss_score}` : ''}</Badge>}
        {item.cvss_score == null && !item.severity && <Badge tone="amber">严重性待补</Badge>}
        {item.is_manual ? <Badge tone="violet">人工添加</Badge> : <Badge tone="sky">自动采集</Badge>}
      </div>
      <p>{item.summary || '暂无摘要。元数据由采集步补齐(pending_fetch 表示还没抓到)。'}</p>
      <ContextDots item={item} />
      <div className="field-grid">
        <InfoField label="CWE" value={item.cwe_ids.join(', ') || '待补'} />
        <InfoField label="受影响产品" value={item.affected_products.join(', ') || '待补'} />
        <InfoField label="修复版本" value={item.fixed_versions.join(', ') || '待补'} />
        <InfoField label="公开时间" value={item.published_at || '未知'} />
        <InfoField label="内容来源" value={item.source || '—'} />
        <InfoField label="登记人" value={item.created_by || '系统'} />
      </div>
      {item.affected_ranges.length > 0 && <p className="small">影响区间:{item.affected_ranges.join(' · ')}</p>}
    </Card>
    <div className="viewbar case-tabs">
      {tabs.map(([id, label, count]) => <button key={id} className={`view-pill ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)} disabled={id !== 'overview' && id !== 'manual_note' && count === 0}>{label}{count ? ` ${count}` : ''}</button>)}
    </div>
    {tab === 'overview' ? <CaseOverview detail={item} onOpenMaterial={onOpenMaterial} onOpenPattern={onOpenPattern} /> : <ContextList type={tab} rows={context[tab] ?? []} />}
    <ManualContextForm caseId={caseId} />
  </div>;
}

function CaseOverview({ detail, onOpenMaterial, onOpenPattern }: { detail: CaseDetail; onOpenMaterial?: (itemId: number) => void; onOpenPattern?: (itemId: number) => void }) {
  const item = detail;
  return <>
    <Card>
      <h3>关联情报素材</h3>
      {detail.materials.length
        ? <div className="timeline">{detail.materials.map(material => <div className="timeline-item" key={material.item_id}><b>{material.title || `素材 #${material.item_id}`}</b><div className="badges">{material.provenance === 'from_material_cve' ? <Badge tone="sky">文章提到该编号</Badge> : material.provenance === 'from_legacy_event' ? <Badge tone="sky">继承素材</Badge> : null}</div><span>{material.source_url ? <a href={material.source_url} target="_blank" rel="noreferrer">{material.source_url}</a> : '无原文链接'}</span>{onOpenMaterial && <button className="btn sm" onClick={() => onOpenMaterial(material.item_id)}>查看素材依据</button>}</div>)}</div>
        : <p className="muted">站内素材库里还没有提到这个编号的文章。采集到的洞会在这里挂上对应的 writeup。</p>}
      <p className="small">这里的关联只说明「文章提到过这个洞」，不代表文章把它讲透了。</p>
    </Card>
    <Card>
      <h3>所属漏洞模式</h3>
      {detail.patterns?.length
        ? <div className="timeline">{detail.patterns.map(pattern => <PatternLinkRow key={pattern.id} pattern={pattern} onOpenPattern={onOpenPattern} />)}</div>
        : <p className="muted">这条案例的文章还没有参与任何模式的抽象（或者它还没有 writeup）。模式库只从文章归纳，不从补丁反推。</p>}
    </Card>
    <Card>
      <h3>外部引用</h3>
      {item.references.length ? <div className="timeline">{item.references.map(url => <div className="timeline-item" key={url}><a href={url} target="_blank" rel="noreferrer">{url}</a></div>)}</div> : <p className="muted">暂无外部引用。</p>}
      {item.aliases.length > 0 && <p className="small">别名:{item.aliases.join(', ')}</p>}
      {item.ghsa_ids.length > 0 && <p className="small">GHSA:{item.ghsa_ids.join(', ')}</p>}
      {item.modified_at && <p className="small">外部记录最后修改:{item.modified_at}(回溯富化按它找该重查的洞)</p>}
    </Card>
    <CaseEditForm detail={item} />
  </>;
}

function PatternLinkRow({ pattern, onOpenPattern }: { pattern: CasePatternLink; onOpenPattern?: (itemId: number) => void }) {
  return <div className="timeline-item">
    <b>{pattern.pattern_name}</b>
    <div className="badges">
      {pattern.cwe_ids.map(cwe => <Badge key={cwe} tone="red">{cwe}</Badge>)}
      <Badge tone="sky">覆盖 {pattern.member_count} 条知识</Badge>
      {pattern.confidence != null && <Badge tone="amber">置信度 {Math.round(pattern.confidence * 100)}%</Badge>}
    </div>
    {onOpenPattern && <button className="btn sm" onClick={() => onOpenPattern(pattern.id)}>查看模式</button>}
  </div>;
}

/**
 * 模式抽屉里的「实例案例」(P6a)。
 *
 * 必须现拉:模式列表接口只带 payload,不带案例;这也是唯一需要跨表 join 的地方
 * (模式 → 知识 → 来源素材 / 编号 → 案例)。空列表不算故障,`note` 会说明原因。
 */
export function PatternCasesCard({ patternItemId, setDrawer }: { patternItemId: number; setDrawer: DrawerSetter }) {
  const cases = useQuery({ queryKey: ['vulnerabilities', 'pattern-cases', patternItemId], queryFn: () => fetchPatternCases(patternItemId) });
  return <Card>
    <h3>实例案例</h3>
    <p className="muted small">口径:该模式来源文章里提到的洞,或挂着同一批文章的真实案例。按公开时间倒序,点条目进案例详情。</p>
    {cases.isLoading && <p className="muted">正在查找…</p>}
    {cases.isError && <p className="muted">实例列表加载失败({String(cases.error)})，模式本身不受影响。</p>}
    {cases.data && !cases.data.items.length && <p className="muted">{cases.data.note || '暂无实例案例。'}</p>}
    {!!cases.data?.items.length && <div className="timeline">
      {cases.data.items.map(item => <button type="button" className="timeline-item clickable" key={item.id} onClick={() => openCaseDrawer(item, setDrawer)}>
        <b>{item.canonical_id}{item.title ? ` · ${item.title}` : ''}</b>
        <div className="badges">
          {item.severity && <Badge tone={severityTone(item.severity)}>{item.severity}</Badge>}
          {item.has_patch ? <Badge tone="green">有补丁</Badge> : null}
          {item.has_vuln_site ? <Badge tone="green">有漏洞点</Badge> : null}
          {item.has_dataflow ? <Badge tone="green">有数据流</Badge> : null}
          {item.why === 'material' ? <Badge tone="sky">来自模式来源文章</Badge> : <Badge>编号相同</Badge>}
        </div>
        {item.materials.length > 0 && <span>{item.materials.map(material => material.title || `素材 #${material.item_id}`).join(' / ')}</span>}
        <span>{item.published_at ? `公开于 ${item.published_at.slice(0, 10)}` : '公开时间未知'}</span>
      </button>)}
    </div>}
    {!!cases.data?.items.length && cases.data.count > cases.data.items.length &&
      <p className="muted small">共 {cases.data.count} 条,这里显示最近 {cases.data.items.length} 条。</p>}
  </Card>;
}

/** 逐字段人工编辑。只列白名单里的键(PATCH 后端会丢掉其余键, 这里也不给入口)。 */
function CaseEditForm({ detail }: { detail: CaseDetail }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [form, setForm] = useState({ title: detail.title, summary: detail.summary, severity: detail.severity, cvss_score: detail.cvss_score == null ? '' : String(detail.cvss_score) });
  const save = useMutation({
    mutationFn: () => updateCase(detail.id, {
      title: form.title.trim(),
      summary: form.summary.trim(),
      severity: form.severity.trim(),
      cvss_score: form.cvss_score.trim() === '' ? null : Number(form.cvss_score),
    }),
    onSuccess: () => { void invalidateCase(qc); toast('已保存', 'success'); },
    onError: error => toast(`保存失败: ${error}`, 'error'),
  });
  return <Card>
    <h3>人工修正元数据</h3>
    <div className="filters">
      <input className="search" value={form.title} placeholder="标题" onChange={event => setForm(f => ({ ...f, title: event.target.value }))} />
      <input className="search" value={form.severity} placeholder="严重性(如 high / 中危)" onChange={event => setForm(f => ({ ...f, severity: event.target.value }))} />
      <input className="search" value={form.cvss_score} placeholder="CVSS 分数(留空 = 未知)" onChange={event => setForm(f => ({ ...f, cvss_score: event.target.value }))} />
    </div>
    <textarea className="search" style={{ width: '100%', minHeight: 70, marginTop: 8, fontFamily: 'inherit' }} value={form.summary} placeholder="摘要(漏洞写清楚就行:影响什么、怎么触发)" onChange={event => setForm(f => ({ ...f, summary: event.target.value }))} />
    <div className="split panel-actions"><button className="btn primary" disabled={save.isPending} onClick={() => save.mutate()}>{save.isPending ? '保存中…' : '保存'}</button></div>
  </Card>;
}

/** 人工补上下文。provenance 由后端固定 manual_added —— 这里不给来源选择, 防止把人的话标成外部事实。 */
function ManualContextForm({ caseId }: { caseId: number }) {
  const { toast } = useToast();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState<{ context_type: CaseContextType; file_path: string; function_name: string; start_line: string; content: string; source_url: string }>({ context_type: 'manual_note', file_path: '', function_name: '', start_line: '', content: '', source_url: '' });
  const submit = useMutation({
    mutationFn: () => addCaseContext(caseId, {
      context_type: form.context_type,
      content: form.content,
      file_path: form.file_path.trim(),
      function_name: form.function_name.trim(),
      start_line: Number(form.start_line) || 0,
      source_url: form.source_url.trim(),
      label: `人工补充(${CONTEXT_LABELS[form.context_type]})`,
    }),
    onSuccess: result => {
      void invalidateCase(qc);
      toast(result.inserted ? '已补充' : '同位置同内容的片段已存在,未重复写入', result.inserted ? 'success' : 'error');
      setForm(f => ({ ...f, content: '' }));
    },
    onError: error => toast(`补充失败: ${error}`, 'error'),
  });
  const needsContent = !form.content.trim() && !form.source_url.trim();
  return <Card>
    <div className="ops-card-title"><div><h3>人工补充上下文</h3><p>补丁片段、漏洞点、数据流都从这里补;<b>来源固定记为「人工补充」</b>,自动采集永远不会覆盖它。</p></div><button className="btn sm" onClick={() => setOpen(value => !value)}>{open ? '收起' : '展开'}</button></div>
    {open && <div style={{ marginTop: 10 }}>
      <div className="filters">
        <select value={form.context_type} onChange={event => setForm(f => ({ ...f, context_type: event.target.value as CaseContextType }))}>
          {(['patch_diff', 'vuln_site', 'dataflow', 'caller_snippet', 'reference', 'manual_note'] as CaseContextType[]).map(type => <option key={type} value={type}>{CONTEXT_LABELS[type]}</option>)}
        </select>
        <input className="search" placeholder="文件路径(如 src/foo.c)" value={form.file_path} onChange={event => setForm(f => ({ ...f, file_path: event.target.value }))} />
        <input className="search" placeholder="函数名" value={form.function_name} onChange={event => setForm(f => ({ ...f, function_name: event.target.value }))} />
        <input className="search" placeholder="起始行号" value={form.start_line} onChange={event => setForm(f => ({ ...f, start_line: event.target.value.replace(/[^0-9]/g, '') }))} />
        <input className="search" placeholder="链接(可选)" value={form.source_url} onChange={event => setForm(f => ({ ...f, source_url: event.target.value }))} />
      </div>
      <textarea className="search" style={{ width: '100%', minHeight: 110, marginTop: 8, fontFamily: 'ui-monospace, monospace' }} value={form.content} placeholder="代码 / diff / 说明原文,原样保存" onChange={event => setForm(f => ({ ...f, content: event.target.value }))} />
      <div className="split panel-actions"><button className="btn primary" disabled={submit.isPending || needsContent} onClick={() => submit.mutate()}>{submit.isPending ? '写入中…' : '写入上下文'}</button></div>
    </div>}
  </Card>;
}

function ContextList({ type, rows }: { type: CaseContextType; rows: CaseContextRow[] }) {
  if (!rows.length) return <EmptyState title={`暂无${CONTEXT_LABELS[type]}`} description="采集步补齐,或在下方人工补充。" />;
  return <Card className="case-context-card">
    <h3>{CONTEXT_LABELS[type]} · {rows.length} 条</h3>
    <div className="grid">
      {rows.map(row => <div className="case-context-row" key={row.id}>
        <div className="badges">
          {provenanceBadge(row.provenance, row.confidence)}
          {row.ref_item_id > 0 && <Badge tone="sky">素材 #{row.ref_item_id}</Badge>}
          {row.file_path && <Badge>{row.file_path}{row.start_line ? `:${row.start_line}${row.end_line && row.end_line !== row.start_line ? `-${row.end_line}` : ''}` : ''}</Badge>}
          {row.function_name && <Badge tone="violet">{row.function_name}()</Badge>}
        </div>
        {row.label && <p className="small">{row.label}</p>}
        {row.content ? <pre className="snippet case-code">{row.content}</pre> : null}
        {row.source_url && <a className="btn sm" href={row.source_url} target="_blank" rel="noreferrer">打开来源</a>}
      </div>)}
    </div>
  </Card>;
}

function InfoField({ label, value }: { label: string; value: string }) {
  return <div className="field"><span>{label}</span><b>{value}</b></div>;
}

export function severityTone(severity: string): 'red' | 'amber' | 'sky' | 'slate' {
  const key = severity.trim().toUpperCase();
  if (key === 'CRITICAL' || key.includes('严重') || key.includes('致命')) return 'red';
  if (key === 'HIGH' || key.includes('高危') || key.includes('高')) return 'amber';
  if (key === 'MEDIUM' || key.includes('中')) return 'sky';
  return 'slate';
}

export function invalidateCase(queryClient: ReturnType<typeof useQueryClient>) {
  return Promise.all([
    queryClient.invalidateQueries({ queryKey: ['vulnerabilities', 'cases'] }),
    queryClient.invalidateQueries({ queryKey: ['vulnerabilities', 'case'] }),
    queryClient.invalidateQueries({ queryKey: ['vulnerabilities', 'today'] }),
  ]);
}

/** 案例抽屉里点「查看素材依据」时的取数: 站内素材按 id 单独拉, 再交给页面现成的素材抽屉。 */
export function openMaterialById(itemId: number, setDrawer: DrawerSetter, openMaterialDrawer: (item: DomainItem<MaterialPayload>, setDrawer: DrawerSetter) => void) {
  void fetchVulnerabilityMaterial(itemId)
    .then(item => openMaterialDrawer(item, setDrawer))
    .catch(() => setDrawer({ title: `素材 #${itemId}`, subtitle: '素材详情加载失败', body: <EmptyState title="素材详情加载失败" description="该素材可能已被清理,或接口暂不可用。" /> }));
}
