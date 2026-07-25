import { useQuery } from '@tanstack/react-query';
import { Card, MetricCard, EmptyState } from '../../components/ui';
import { getJson } from '../../api/client';
import '../../styles/capability.css';

interface OpsData {
  stats: { total: number; candidates: number; capabilities: number; conversions: number; repro_succeeded: number; repro_active: number };
  classify_stats: { total: number; classified: number; unclassified: number; web_count: number };
  repro_failures: { total_failed: number; by_status: Record<string, number>; details: Array<{ task_id: number; item_id: number; status: string; reason: string }> };
  missing_fields: { total_audited: number; missing_counts: Record<string, number>; details: Record<string, Array<{ id: number; title: string }>> };
}

function fetchOpsOverview(): Promise<OpsData> {
  return getJson<OpsData>('/api/capabilities/ops/overview');
}

export function CapabilityOps() {
  const { data, isLoading } = useQuery({ queryKey: ['cap-ops'], queryFn: fetchOpsOverview, staleTime: 5000 });

  if (isLoading || !data) return <p className="muted">加载中...</p>;

  const { stats, classify_stats, repro_failures, missing_fields } = data;

  return <div className="grid" style={{ paddingBottom: 48 }}>
    {/* KPI 行 */}
    <div className="grid cols-4">
      <MetricCard label="能力库" value={stats.capabilities} hint="已评分能力资产" tone="green" />
      <MetricCard label="复现任务" value={stats.repro_succeeded + stats.repro_active} hint={`成功 ${stats.repro_succeeded} · 活跃 ${stats.repro_active}`} tone="amber" />
      <MetricCard label="转化记录" value={stats.conversions} hint="待集成/待二开" tone="violet" />
      <MetricCard label="Web 分类" value={classify_stats.classified} hint={`总计 ${classify_stats.total} · Web ${classify_stats.web_count}`} tone="sky" />
    </div>

    {/* 2 列：复现失败 + 缺字段审计 */}
    <div className="grid cols-2" style={{ marginTop: 12 }}>
      {/* 复现失败审计 */}
      <div className="panel">
        <div className="panel-head"><h3>复现失败审计</h3><span>{repro_failures.total_failed} 个失败</span></div>
        <div className="panel-body">
          {repro_failures.total_failed === 0
            ? <EmptyState title="无失败任务" description="所有复现任务状态正常" />
            : <div className="table-card"><table className="data-table"><thead><tr><th>任务</th><th>状态</th><th>原因</th></tr></thead><tbody>
                {repro_failures.details.map((f) => (
                  <tr key={f.task_id}>
                    <td><div className="table-title">task-{f.task_id}</div><div className="table-sub">item: {f.item_id}</div></td>
                    <td><span className="status-tag hot">{f.status}</span></td>
                    <td className="small muted">{f.reason}</td>
                  </tr>
                ))}
              </tbody></table></div>
          }
        </div>
      </div>

      {/* 能力卡缺字段审计 */}
      <div className="panel">
        <div className="panel-head"><h3>能力卡缺字段审计</h3><span>{missing_fields.total_audited} 个已审计</span></div>
        <div className="panel-body">
          <div className="field-grid">
            {Object.entries(missing_fields.missing_counts).map(([field, count]) => {
              const pct = missing_fields.total_audited > 0 ? Math.round((count / missing_fields.total_audited) * 100) : 0;
              return <div className="cap-field" key={field}>
                <span>{field}</span>
                <b style={{ color: count > 0 ? 'var(--amber)' : 'var(--green)' }}>{count} 缺失 ({pct}%)</b>
              </div>;
            })}
          </div>
        </div>
      </div>
    </div>

    {/* Web 分类统计 */}
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
