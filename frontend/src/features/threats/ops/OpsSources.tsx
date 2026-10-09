/**
 * 数据源页(2026-10-08 领导反馈 #5 重做)。
 *
 * 旧版只有 7 个裸标识(ascendhub / firmware / repos …),看不出"到底从哪些网站取数据"。
 * 现在一行 = 一个数据源(具体到站点),列出自哪个网站、走哪个采集步骤、包含哪些采集目标、
 * 采了多少条、最近一次采集时间;并支持人工添加采集目标(立刻生效)与登记新数据源(待接入)。
 */
import { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Card } from '../../../components/ui';
import { useToast } from '../../../components/Toast';
import {
  addSourceSite, addSourceTarget, deleteSourceTarget, fetchOpsSources, setSourceTargetEnabled,
  type OpsSourceGroup, type OpsSourceTarget,
} from '../../../api/opsClient';

type AddMode = 'target' | 'site';

const KIND_LABEL: Record<string, string> = { repo: '代码仓', asset: '资产', vuln: '漏洞', material: '安全素材' };

const STATUS_BADGE: Record<OpsSourceGroup['status'], string> = { ok: 'success', stale: 'warn', never: 'info', pending: 'warn' };
// 采集每天一轮,所以"非当天"就该报黄(后端 _status 的口径与此一致:只有 days_ago==0 才是 ok)
const STATUS_TEXT: Record<OpsSourceGroup['status'], string> = { ok: '今日已采集', stale: '超过 1 天未采集', never: '从未采集', pending: '待接入' };

export function OpsSources() {
  const { data, isLoading } = useQuery({ queryKey: ['ops-sources'], queryFn: fetchOpsSources, staleTime: 10000 });
  const qc = useQueryClient();
  const { toast, confirm } = useToast();
  const [addOpen, setAddOpen] = useState(false);
  const [mode, setMode] = useState<AddMode>('target');
  const [form, setForm] = useState({ source_key: '', identifier: '', label: '', site_url: '', note: '' });

  const refresh = () => { void qc.invalidateQueries({ queryKey: ['ops-sources'] }); };

  const addTarget = useMutation({
    mutationFn: () => addSourceTarget({ source_key: form.source_key, identifier: form.identifier.trim(), label: form.label.trim() }),
    onSuccess: (res) => { toast(`已添加采集目标 ${res.target.identifier},下一轮采集生效`, 'success'); setForm(f => ({ ...f, identifier: '', label: '' })); refresh(); },
    onError: (e) => toast(`添加失败: ${e}`, 'error'),
  });
  const addSite = useMutation({
    mutationFn: () => addSourceSite({ site_url: form.site_url.trim(), label: form.label.trim(), note: form.note.trim() }),
    onSuccess: (res) => { toast(`已登记数据源「${res.source.label}」,需开发采集器后才会产生数据`, 'success'); setForm(f => ({ ...f, site_url: '', label: '', note: '' })); refresh(); },
    onError: (e) => toast(`登记失败: ${e}`, 'error'),
  });
  const toggleTarget = useMutation({
    mutationFn: (t: OpsSourceTarget) => setSourceTargetEnabled(t.id as number, !t.enabled),
    onSuccess: (res) => { toast(res.enabled ? '已启用,下轮采集包含' : '已停用,下轮采集不再包含', 'success'); refresh(); },
    onError: (e) => toast(`操作失败: ${e}`, 'error'),
  });
  const removeTarget = useMutation({
    mutationFn: (id: number) => deleteSourceTarget(id),
    onSuccess: () => { toast('已删除', 'success'); refresh(); },
    onError: (e) => toast(`删除失败: ${e}`, 'error'),
  });

  if (isLoading || !data) return <p className="muted">加载中...</p>;

  const groups = data.groups;
  const pending = data.pending_sources;
  const addable = data.addable_keys;
  const enabledTargets = groups.reduce((sum, g) => sum + g.targets.filter(t => t.enabled).length, 0);
  const todayCount = groups.filter(g => g.days_ago === 0).length;

  const submit = async () => {
    if (mode === 'target') {
      if (!form.identifier.trim()) { toast('请填写要添加的标识(组织名 / hub id)', 'error'); return; }
      addTarget.mutate();
    } else {
      if (!form.site_url.trim() || !form.label.trim()) { toast('请填写站点 URL 和名称', 'error'); return; }
      addSite.mutate();
    }
  };

  const askRemove = async (t: OpsSourceTarget) => {
    const ok = await confirm(`确认删除人工添加的采集目标「${t.label || t.identifier}」?\n删除后下一轮采集不再包含它。`);
    if (ok && t.id != null) removeTarget.mutate(t.id);
  };

  return (
    <div className="grid" style={{ paddingBottom: 48 }}>
      <div className="grid cols-4">
        <Card className="kpi"><span>数据源</span><strong>{groups.length}</strong><p>具体站点/接口</p></Card>
        <Card className="kpi"><span>采集目标</span><strong>{enabledTargets}</strong><p>已启用的组织 / hub</p></Card>
        <Card className="kpi"><span>今日已采集</span><strong>{todayCount}</strong><p>共 {groups.length} 个数据源</p></Card>
        <Card className="kpi"><span>总记录数</span><strong>{data.total_records}</strong><p>原始采集条目</p></Card>
      </div>

      <Card style={{ marginTop: 12 }}>
        <div className="row-title">
          <h3>人工添加</h3>
          <button className="btn sm" onClick={() => setAddOpen(v => !v)}>{addOpen ? '收起' : '展开表单'}</button>
        </div>
        <p className="muted small" style={{ marginTop: 6 }}>
          添加<b>采集目标</b>:选一个既有数据源,填组织名或 hub id,下一轮采集立刻带上,不需要改代码。
          登记<b>新数据源</b>:只落库列在下面,要真正取到数据还得开发对应的采集器(平台不会自动发现新站点)。
        </p>
        {addOpen && (
          <div style={{ marginTop: 10 }}>
            <div className="assoc-seg" style={{ marginBottom: 10 }}>
              <button className={mode === 'target' ? 'on' : ''} onClick={() => setMode('target')}>添加采集目标</button>
              <button className={mode === 'site' ? 'on' : ''} onClick={() => setMode('site')}>登记新数据源</button>
            </div>

            {mode === 'target' ? (
              <div className="filters">
                <select className="select" value={form.source_key || addable[0]?.key || ''} onChange={e => setForm(f => ({ ...f, source_key: e.target.value }))}>
                  {addable.map(k => <option key={k.key} value={k.key}>{k.name}</option>)}
                </select>
                <input className="search" value={form.identifier} placeholder={addable.find(k => k.key === (form.source_key || addable[0]?.key))?.hint ?? '组织名 / hub id'}
                  onChange={e => setForm(f => ({ ...f, identifier: e.target.value }))} />
                <input className="search" value={form.label} placeholder="备注名称(可空)" onChange={e => setForm(f => ({ ...f, label: e.target.value }))} />
                <button className="btn primary" disabled={addTarget.isPending} onClick={submit}>{addTarget.isPending ? '提交中…' : '添加'}</button>
              </div>
            ) : (
              <div className="filters">
                <input className="search" value={form.site_url} placeholder="站点 URL,如 https://gitcode.com" onChange={e => setForm(f => ({ ...f, site_url: e.target.value }))} />
                <input className="search" value={form.label} placeholder="数据源名称" onChange={e => setForm(f => ({ ...f, label: e.target.value }))} />
                <input className="search" value={form.note} placeholder="说明(取什么数据、为什么加)" onChange={e => setForm(f => ({ ...f, note: e.target.value }))} />
                <button className="btn primary" disabled={addSite.isPending} onClick={submit}>{addSite.isPending ? '提交中…' : '登记'}</button>
              </div>
            )}
          </div>
        )}
      </Card>

      <Card style={{ marginTop: 12 }}>
        <h3>数据源明细</h3>
        <p className="muted small" style={{ marginTop: 4 }}>一行 = 一个数据源(具体站点)。展开「采集目标」可看它到底抓哪些组织,人工加过的会标出添加人。</p>
        <div className="table-card" style={{ marginTop: 10 }}>
          <table>
            <thead><tr><th>数据源</th><th>采集站点</th><th>类型</th><th>采集目标</th><th>记录数</th><th>最近采集</th><th>状态</th></tr></thead>
            <tbody>
              {groups.map(g => (
                <tr key={g.key}>
                  <td style={{ maxWidth: 210 }}>
                    <div className="repo-name">{g.name}</div>
                    <div className="muted small">{g.collector}</div>
                  </td>
                  <td style={{ maxWidth: 220 }}>
                    <div className="repo-url" style={{ wordBreak: 'break-all' }}>
                      {g.entry_url ? <a className="repo-url" href={g.entry_url} target="_blank" rel="noreferrer">{g.site}</a> : g.site}
                    </div>
                    <div className="muted small">{g.note}</div>
                  </td>
                  <td><span className="badge">{KIND_LABEL[g.kind] ?? g.kind}</span></td>
                  <td style={{ maxWidth: 320 }}>
                    {g.targets.length ? (
                      <div className="split" style={{ gap: 4, flexWrap: 'wrap', justifyContent: 'flex-start' }}>
                        {g.targets.map(t => (
                          <span key={`${t.source_key}:${t.identifier}`} className="badge" title={t.builtin ? '代码内置目标' : `人工添加${t.created_by ? ` by ${t.created_by}` : ''}${t.created_at ? ` · ${t.created_at.slice(0, 10)}` : ''}`}
                            style={t.enabled ? undefined : { opacity: 0.45, textDecoration: 'line-through' }}>
                            {t.label || t.identifier}{t.builtin ? '' : ' ·人工'}
                          </span>
                        ))}
                      </div>
                    ) : <span className="muted small">—</span>}
                  </td>
                  <td className="mono">{g.records}</td>
                  <td className="small muted">{g.last_sync ? `${g.last_sync}${g.days_ago != null ? `(${g.days_ago === 0 ? '今天' : `${g.days_ago} 天前`})` : ''}` : '—'}</td>
                  <td><span className={`badge ${STATUS_BADGE[g.status]}`}>{STATUS_TEXT[g.status]}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card style={{ marginTop: 12 }}>
        <div className="row-title">
          <h3>人工添加的采集目标</h3>
          <span className="muted tiny">可停用 / 删除;停用后下一轮采集不再包含</span>
        </div>
        {(() => {
          const manual = groups.flatMap(g => g.targets.filter(t => !t.builtin).map(t => ({ ...t, sourceName: g.name })));
          if (!manual.length) return <p className="muted small" style={{ marginTop: 8 }}>还没有人工添加的采集目标。</p>;
          return (
            <div className="timeline" style={{ marginTop: 8 }}>
              {manual.map(t => (
                <div key={t.id ?? t.identifier} className="timeline-item">
                  <div className="row-title">
                    <span><b>{t.label || t.identifier}</b> <span className="muted small">{t.identifier} · {t.sourceName}</span></span>
                    <span>
                      <span className={`badge ${t.enabled ? 'success' : 'warn'}`}>{t.enabled ? '启用' : '已停用'}</span>
                      <button className="btn sm" style={{ marginLeft: 6 }} onClick={() => toggleTarget.mutate(t)}>{t.enabled ? '停用' : '启用'}</button>
                      <button className="btn sm" style={{ marginLeft: 6 }} onClick={() => askRemove(t)}>删除</button>
                    </span>
                  </div>
                  <span className="muted small">添加人:{t.created_by || '未知'} · {t.created_at?.slice(0, 19) || ''}</span>
                </div>
              ))}
            </div>
          );
        })()}
      </Card>

      <Card style={{ marginTop: 12 }}>
        <div className="row-title">
          <h3>已登记、待接入的数据源</h3>
          <span className="muted tiny">登记 ≠ 已采集;这些站点还没有对应的采集器</span>
        </div>
        {pending.length ? (
          <div className="timeline" style={{ marginTop: 8 }}>
            {pending.map(s => (
              <div key={s.id ?? s.identifier} className="timeline-item">
                <div className="row-title">
                  <span><b>{s.label || s.identifier}</b> <span className="muted small">{s.identifier}</span></span>
                  <span className="badge warn">待接入</span>
                </div>
                <span className="muted small">登记人:{s.created_by || '未知'} · {s.created_at?.slice(0, 19) || ''}</span>
              </div>
            ))}
          </div>
        ) : <p className="muted small" style={{ marginTop: 8 }}>暂无。</p>}
      </Card>
    </div>
  );
}
