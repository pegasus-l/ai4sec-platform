import { useQuery } from '@tanstack/react-query';
import { Card } from '../../../components/ui';
import { fetchOpsSources } from '../../../api/opsClient';

export function OpsSources() {
  const { data, isLoading } = useQuery({ queryKey: ['ops-sources'], queryFn: fetchOpsSources, staleTime: 10000 });

  if (isLoading || !data) return <p className="muted">加载中...</p>;

  const sources = data.items;

  return (
    <div className="grid">
      <div className="grid cols-3">
        <Card className="kpi"><span>总数据源</span><strong>{sources.length}</strong></Card>
        <Card className="kpi"><span>最近采集</span><strong>{sources.filter(s => s.days_ago === 0).length}</strong><p>今天</p></Card>
        <Card className="kpi"><span>总记录数</span><strong>{sources.reduce((a, s) => a + s.total_items, 0)}</strong></Card>
      </div>

      <Card style={{ marginTop: 12 }}>
        <h3>数据源状态</h3>
        <div className="table-card" style={{ marginTop: 10 }}>
          <table>
            <thead><tr><th>数据源</th><th>记录数</th><th>最近采集</th><th>距今</th><th>状态</th></tr></thead>
            <tbody>
              {sources.map((s) => (
                <tr key={s.source}>
                  <td><div className="repo-name">{s.source}</div></td>
                  <td className="mono">{s.total_items}</td>
                  <td className="small muted">{s.last_sync}</td>
                  <td><span className={`badge ${s.days_ago === 0 ? 'success' : s.days_ago && s.days_ago > 2 ? 'warn' : 'info'}`}>{s.days_ago === 0 ? '今天' : `${s.days_ago} 天前`}</span></td>
                  <td><span className="badge success">启用</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
