import { useQuery } from '@tanstack/react-query';
import { Card } from '../../../components/ui';
import { fetchManualQueue } from '../../../api/opsClient';

export function OpsManualQueue() {
  const { data, isLoading } = useQuery({ queryKey: ['ops-manual-queue'], queryFn: fetchManualQueue, staleTime: 10000 });

  if (isLoading || !data) return <p className="muted">加载中...</p>;

  const kpis = data.kpis;
  const items = data.items;

  const priorityLabel = (p: number) => p === 1 ? 'P0' : p === 2 ? 'P1' : p === 3 ? 'P2' : `P${p}`;
  const statusBadge = (s: string) => {
    if (s.includes('待') || s === 'pending') return <span className="badge B">待处理</span>;
    if (s.includes('跟踪') || s.includes('审')) return <span className="badge A">处理中</span>;
    if (s.includes('关')) return <span className="badge">已关闭</span>;
    return <span className="badge">{s}</span>;
  };

  return (
    <div className="grid">
      <div className="grid cols-4">
        <Card className="kpi"><span>待处理</span><strong>{kpis.pending}</strong></Card>
        <Card className="kpi"><span>处理中</span><strong>{kpis.reviewing}</strong></Card>
        <Card className="kpi"><span>已关闭</span><strong>{kpis.closed}</strong></Card>
        <Card className="kpi"><span>总计</span><strong>{data.total}</strong></Card>
      </div>

      <Card style={{ marginTop: 12 }}>
        <h3>人工队列（pipeline 自动入库）</h3>
        <p className="muted small">pipeline 识别的高风险目标自动进入此队列，等待人工研判、确认或跟踪。</p>
        <div className="table-card" style={{ marginTop: 10 }}>
          <table>
            <thead><tr><th>目标</th><th>类型</th><th>优先级</th><th>状态</th><th>入库原因</th><th>时间</th></tr></thead>
            <tbody>
              {items.map((q) => (
                <tr key={q.id}>
                  <td>
                    <div className="repo-name">{q.title || `#${q.item_id}`}</div>
                    {q.url && <div className="repo-url">{q.url}</div>}
                  </td>
                  <td><span className="badge">{q.queue_type}</span></td>
                  <td><span className={`badge ${q.priority === 1 ? 'A' : 'B'}`}>{priorityLabel(q.priority)}</span></td>
                  <td>{statusBadge(q.status)}</td>
                  <td className="small muted" style={{ maxWidth: 300 }}>{q.reason}</td>
                  <td className="small muted">{q.created_at?.slice(0, 16)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
