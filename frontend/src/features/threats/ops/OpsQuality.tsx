import { useQuery } from '@tanstack/react-query';
import { Card } from '../../../components/ui';
import { fetchOpsQuality } from '../../../api/opsClient';

export function OpsQuality() {
  const { data, isLoading } = useQuery({ queryKey: ['ops-quality'], queryFn: fetchOpsQuality, staleTime: 10000 });

  if (isLoading || !data) return <p className="muted">加载中...</p>;

  const kpis = data.kpis;
  const items = data.items;

  return (
    <div className="grid">
      <div className="grid cols-4">
        <Card className="kpi"><span>总审计</span><strong>{kpis.total}</strong></Card>
        <Card className="kpi"><span>通过</span><strong>{kpis.passed}</strong></Card>
        <Card className="kpi"><span>预警</span><strong>{kpis.warned}</strong></Card>
        <Card className="kpi"><span>失败</span><strong>{kpis.failed}</strong></Card>
      </div>

      <Card style={{ marginTop: 12 }}>
        <h3>质量审计记录</h3>
        <div className="table-card" style={{ marginTop: 10 }}>
          <table>
            <thead><tr><th>类型</th><th>状态</th><th>分数</th><th>说明</th><th>时间</th></tr></thead>
            <tbody>
              {items.map((q) => (
                <tr key={q.id}>
                  <td><div className="repo-name">{q.audit_type}</div></td>
                  <td><span className={`badge ${q.status === 'pass' ? 'success' : q.status === 'warn' ? 'warn' : 'failed'}`}>{q.status}</span></td>
                  <td className="mono">{(q.score * 100).toFixed(0)}%</td>
                  <td className="small muted">{q.summary.slice(0, 100)}</td>
                  <td className="small muted">{q.created_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
