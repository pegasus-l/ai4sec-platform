import { useQuery } from '@tanstack/react-query';
import { useState } from 'react';
import { Card, MetricCard, EmptyState, Drawer } from '../../components/ui';
import { getJson } from '../../api/client';
import { fetchRuns, fetchRunDetail, type OpsRun } from '../../api/opsClient';
import '../../styles/capability.css';

interface OpsData {
  stats: { total: number; candidates: number; capabilities: number; conversions: number; repro_succeeded: number; repro_active: number };
  classify_stats: { total: number; classified: number; unclassified: number; web_count: number };
  repro_failures: { total_failed: number; by_status: Record<string, number>; details: Array<{ task_id: number; item_id: number; status: string; reason: string }> };
  missing_fields: { total_audited: number; missing_counts: Record<string, number>; details: Record<string, Array<{ id: number; title: string }>> };
}

function fetchOpsOverview(): Promise<OpsData> { return getJson<OpsData>('/api/capabilities/ops/overview'); }
function fetchReproFailures() { return getJson<OpsData['repro_failures']>('/api/capabilities/ops/repro-failures'); }
function fetchMissingFields() { return getJson<OpsData['missing_fields']>('/api/capabilities/ops/missing-fields'); }

// ========== 1. 运营概览 ==========
export function CapabilityOps() {
  const { data, isLoading } = useQuery({ queryKey: ['cap-ops'], queryFn: fetchOpsOverview, staleTime: 5000 });
  if (isLoading || !data) return <p className="muted">加载中...</p>;
  const { stats, classify_stats, repro_failures, missing_fields } = data;

  return <div className="grid" style={{ paddingBottom: 48 }}>
    <div className="grid cols-4">
      <MetricCard label="能力库" value={stats.capabilities} hint="已评分能力资产" tone="green" />
      <MetricCard label="复现任务" value={stats.repro_succeeded + stats.repro_active} hint={`成功 ${stats.repro_succeeded} · 活跃 ${stats.repro_active}`} tone="amber" />
      <MetricCard label="转化记录" value={stats.conversions} hint="待集成/待二开" tone="violet" />
      <MetricCard label="Web 分类" value={classify_stats.classified} hint={`总计 ${classify_stats.total} · Web ${classify_stats.web_count}`} tone="sky" />
    </div>

    <div className="grid cols-2" style={{ marginTop: 12 }}>
      <div className="panel">
        <div className="panel-head"><h3>复现失败审计</h3><span>{repro_failures.total_failed} 个失败</span></div>
        <div className="panel-body">
          {repro_failures.total_failed === 0
            ? <EmptyState title="无失败任务" description="所有复现任务状态正常" />
            : <div className="table-card"><table className="data-table"><thead><tr><th>任务</th><th>状态</th><th>原因</th></tr></thead><tbody>
                {repro_failures.details.slice(0, 5).map((f) => (<tr key={f.task_id}><td><div className="table-title">task-{f.task_id}</div><div className="table-sub">item: {f.item_id}</div></td><td><span className="status-tag hot">{f.status}</span></td><td className="small muted">{f.reason}</td></tr>))}
              </tbody></table></div>}
        </div>
      </div>
      <div className="panel">
        <div className="panel-head"><h3>能力卡缺字段审计</h3><span>{missing_fields.total_audited} 个已审计</span></div>
        <div className="panel-body">
          <div className="field-grid">
            {Object.entries(missing_fields.missing_counts).map(([field, count]) => { const pct = missing_fields.total_audited > 0 ? Math.round((count / missing_fields.total_audited) * 100) : 0; return <div className="cap-field" key={field}><span>{field}</span><b style={{ color: count > 0 ? 'var(--amber)' : 'var(--green)' }}>{count} 缺失 ({pct}%)</b></div>; })}
          </div>
        </div>
      </div>
    </div>

    <div className="panel" style={{ marginTop: 12 }}>
      <div className="panel-head"><h3>Web 分类统计</h3><span>规则预筛 + DeepSeek LLM 判断</span></div>
      <div className="panel-body">
        <div className="grid cols-4">
          <Card className="kpi"><span>总项目</span><strong>{classify_stats.total}</strong></Card>
          <Card className="kpi"><span>已分类</span><strong>{classify_stats.classified}</strong></Card>
          <Card className="kpi"><span>未分类</span><strong>{classify_stats.unclassified}</strong></Card>
          <Card className="kpi"><span>Web 项目</span><strong>{classify_stats.web_count}</strong></Card>
        </div>
      </div>
    </div>
  </div>;
}

// ========== 2. 质量审计 ==========
export function CapabilityOpsQuality() {
  const { data: failures } = useQuery({ queryKey: ['cap-ops-repro-failures'], queryFn: fetchReproFailures, staleTime: 10000 });
  const { data: missing } = useQuery({ queryKey: ['cap-ops-missing-fields'], queryFn: fetchMissingFields, staleTime: 10000 });
  const { data: overview } = useQuery({ queryKey: ['cap-ops-overview-quality'], queryFn: fetchOpsOverview, staleTime: 10000 });

  const classify = overview?.classify_stats ?? { total: 0, classified: 0, unclassified: 0, web_count: 0 };

  return <div className="grid" style={{ paddingBottom: 48 }}>
    <div className="grid cols-4">
      <MetricCard label="复现失败" value={failures?.total_failed ?? 0} hint="failed/timeout/stopped" tone="red" />
      <MetricCard label="已审计能力卡" value={missing?.total_audited ?? 0} hint="6 字段完整性检查" tone="amber" />
      <MetricCard label="Web 分类" value={classify.classified} hint={`总计 ${classify.total}`} tone="sky" />
      <MetricCard label="未分类" value={classify.unclassified} hint="待批量 Web 分类" tone="violet" />
    </div>

    {/* 复现失败详情 */}
    <div className="panel" style={{ marginTop: 12 }}>
      <div className="panel-head"><h3>复现失败详情</h3><span>{failures?.total_failed ?? 0} 个失败任务</span></div>
      <div className="panel-body">
        {(!failures || failures.total_failed === 0)
          ? <EmptyState title="无失败任务" description="所有复现任务状态正常" />
          : <div className="table-card"><table className="data-table"><thead><tr><th>任务 ID</th><th>能力 ID</th><th>状态</th><th>失败原因</th></tr></thead><tbody>
              {failures.details.map((f) => (<tr key={f.task_id}>
                <td><div className="table-title">task-{f.task_id}</div></td>
                <td>{f.item_id}</td>
                <td><span className={`status-tag ${f.status === 'failed' ? 'hot' : 'warn'}`}>{f.status}</span></td>
                <td className="small muted">{f.reason}</td>
              </tr>))}
            </tbody></table></div>}
      </div>
    </div>

    {/* 缺字段详情 */}
    <div className="panel" style={{ marginTop: 12 }}>
      <div className="panel-head"><h3>能力卡缺字段详情</h3><span>{missing?.total_audited ?? 0} 个已审计</span></div>
      <div className="panel-body">
        {!missing ? <p className="muted">加载中...</p> :
          Object.entries(missing.missing_counts).map(([field, count]) => {
            const missingItems = missing.details[field] ?? [];
            return <div className="panel" key={field} style={{ marginTop: 8 }}>
              <div className="panel-head"><h3>{field}</h3><span className="status-tag warn">{count} 缺失</span></div>
              <div className="panel-body">
                {missingItems.length === 0 ? <p className="muted small">无缺失</p> :
                  <div className="table-card"><table className="data-table"><thead><tr><th>ID</th><th>标题</th></tr></thead><tbody>
                    {missingItems.map((item) => (<tr key={item.id}><td>{item.id}</td><td><div className="table-title">{item.title}</div></td></tr>))}
                  </tbody></table></div>}
              </div>
            </div>;
          })}
      </div>
    </div>
  </div>;
}

// ========== 3. Pipeline 运行 ==========
const capPipelineNames: Record<string, string> = {
  'capabilities.from_news_pipeline': '能力派生（资讯→能力候选→评估）',
  'capabilities.web_classify_pipeline': 'Web 分类（规则+DeepSeek）',
  'capabilities.repro_pipeline': '复现验证（docker+sysbox）',
  'capabilities.conversion_pipeline': '能力转化（状态推进）',
};

export function CapabilityOpsRuns() {
  const { data, isLoading } = useQuery({ queryKey: ['cap-ops-runs'], queryFn: fetchRuns, staleTime: 5000 });
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const { data: runDetail, isLoading: detailLoading } = useQuery({
    queryKey: ['cap-ops-run-detail', selectedRunId],
    queryFn: () => selectedRunId ? fetchRunDetail(selectedRunId) : Promise.resolve(null as unknown as OpsRun),
    enabled: !!selectedRunId,
  });

  // 过滤 capabilities 域的运行
  const capRuns = (data?.items ?? []).filter((r) => r.pipeline_name?.includes('capabilit'));
  const running = capRuns.filter((r) => r.status === 'running');
  const failed = capRuns.filter((r) => r.status === 'failed');
  const succeeded = capRuns.filter((r) => r.status === 'success');

  return <div className="grid" style={{ paddingBottom: 48 }}>
    <div className="grid cols-4">
      <MetricCard label="总运行" value={capRuns.length} hint="能力洞察 pipeline" tone="sky" />
      <MetricCard label="运行中" value={running.length} hint="当前活跃" tone="green" />
      <MetricCard label="成功" value={succeeded.length} hint="已完成" tone="green" />
      <MetricCard label="失败" value={failed.length} hint="需检查" tone="red" />
    </div>

    <div className="panel" style={{ marginTop: 12 }}>
      <div className="panel-head"><h3>能力洞察 Pipeline 运行历史</h3><span>{capRuns.length} 次运行</span></div>
      <div className="panel-body">
        {isLoading ? <p className="muted">加载中...</p> :
        capRuns.length === 0 ? <EmptyState title="暂无运行记录" description="运行 capabilities.from_news_pipeline 等 pipeline 后将在这里显示" /> :
        <div className="table-card"><table className="data-table"><thead><tr><th>Pipeline</th><th>状态</th><th>开始时间</th><th>结束时间</th></tr></thead><tbody>
          {capRuns.map((r) => (
            <tr key={r.run_id} className="clickable" onClick={() => setSelectedRunId(r.run_id)}>
              <td><div className="table-title">{capPipelineNames[r.pipeline_name] ?? r.pipeline_name}</div><div className="table-sub">{r.run_id.slice(0, 12)}…</div></td>
              <td><span className={`status-tag ${r.status === 'success' ? 'good' : r.status === 'failed' ? 'hot' : r.status === 'running' ? '' : 'warn'}`}>{r.status}</span></td>
              <td className="small muted">{r.started_at?.replace('T', ' ').slice(0, 19) ?? '—'}</td>
              <td className="small muted">{r.finished_at?.replace('T', ' ').slice(0, 19) ?? '—'}</td>
            </tr>
          ))}
        </tbody></table></div>}
      </div>
    </div>

    <Drawer open={!!selectedRunId} title={runDetail?.pipeline_name ?? '运行详情'} subtitle={selectedRunId ?? ''} onClose={() => setSelectedRunId(null)}>
      {detailLoading ? <p className="muted">加载运行详情...</p> : runDetail && <>
        <div className="panel"><div className="panel-head"><h3>运行状态</h3><span className={`status-tag ${runDetail.status === 'success' ? 'good' : runDetail.status === 'failed' ? 'hot' : ''}`}>{runDetail.status}</span></div><div className="panel-body">
          <p className="muted small">{runDetail.started_at?.replace('T', ' ').slice(0, 19)} → {runDetail.finished_at?.replace('T', ' ').slice(0, 19)}</p>
          {runDetail.tasks && runDetail.tasks.length > 0 && <div style={{ marginTop: 10 }}>
            <strong>步骤 ({runDetail.tasks.length})</strong>
            <div className="cap-steps" style={{ marginTop: 8 }}>
              {runDetail.tasks.map((task, i) => { const t = task as Record<string, unknown>; return <div className="cap-step" key={i}><span className={`status-tag ${String(t.status) === 'success' ? 'good' : String(t.status) === 'failed' ? 'hot' : 'warn'}`}>{String(t.status ?? 'unknown')}</span> {String(t.step_name ?? `step-${i}`)}</div>; })}
            </div>
          </div>}
          {runDetail.artifacts && runDetail.artifacts.length > 0 && <div style={{ marginTop: 10 }}>
            <strong>产物 ({runDetail.artifacts.length})</strong>
            {runDetail.artifacts.map((a, i) => { const art = a as Record<string, unknown>; return <div key={i} className="small muted" style={{ marginTop: 4 }}>• {String(art.artifact_type ?? art.path ?? 'artifact')}</div>; })}
          </div>}
        </div></div>
      </>}
    </Drawer>
  </div>;
}
