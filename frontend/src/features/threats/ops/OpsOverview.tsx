import { useQuery } from '@tanstack/react-query';
import { Card } from '../../../components/ui';
import { fetchOpsOverview } from '../../../api/opsClient';
import type { ThreatViewModel } from '../../../types/threat';
import type { ViewId } from '../ThreatPage';

interface Props {
  model: ThreatViewModel;
  setView: (view: ViewId) => void;
}

export function OpsOverview({ setView }: Props) {
  const { data, isLoading } = useQuery({ queryKey: ['ops-overview'], queryFn: fetchOpsOverview, staleTime: 5000 });

  if (isLoading || !data) return <p className="muted">加载中...</p>;

  const stats = data.db_stats;
  const lastRun = data.last_run;
  const ai = data.ai_stats;

  return (
    <div className="grid" style={{ paddingBottom: 48 }}>
      <div className="grid cols-3">
        <Card className="kpi"><span>代码仓</span><strong>{stats.repos}</strong><p>资产 {stats.assets} · 队列 {stats.queue}</p></Card>
        <Card className="kpi"><span>AI 研判 / 资产关联</span><strong>{ai.ai_reviews} / {ai.asset_associations}</strong><p>证据 {stats.evidence_items} · 审计 {stats.quality_audits}</p></Card>
        <Card className="kpi"><span>上次 Pipeline</span><strong>{lastRun ? lastRun.status : '—'}</strong><p>{lastRun ? `${lastRun.days_ago} 天前` : '无记录'}</p></Card>
      </div>

      <div className="grid cols-2" style={{ marginTop: 12 }}>
        <Card>
          <h3>上次 Pipeline 运行</h3>
          {lastRun ? (
            <div>
              <div className="split"><span className={`badge ${lastRun.status === 'success' ? 'success' : lastRun.status === 'failed' ? 'failed' : 'running'}`}>{lastRun.status}</span><span className="muted small">{lastRun.days_ago} 天前</span></div>
              <p className="muted small" style={{ marginTop: 8 }}>{lastRun.pipeline}</p>
              <p className="muted small">{lastRun.started_at} → {lastRun.finished_at}</p>
              <button className="btn sm" style={{ marginTop: 8 }} onClick={() => setView('ops-tasks')}>查看运行历史</button>
            </div>
          ) : <p className="muted">暂无运行记录</p>}
        </Card>
        <Card>
          <h3>AI 分析进度</h3>
          <div className="asset-meta">
            <div><b>{ai.ai_reviews}</b><span>AI 研判</span></div>
            <div><b>{ai.asset_associations}</b><span>资产关联</span></div>
            <div><b>{stats.repos}</b><span>总代码仓</span></div>
            <div><b>{stats.assets}</b><span>总资产</span></div>
          </div>
          <button className="btn sm primary" style={{ marginTop: 8 }} onClick={() => setView('ops-ai-summary')}>查看 AI 汇总</button>
        </Card>
      </div>

      <div className="grid cols-3" style={{ marginTop: 12 }}>
        <Card>
          <h3>快捷操作</h3>
          <div style={{ display: 'grid', gap: 8, marginTop: 10 }}>
            <button className="btn primary" onClick={() => setView('ops-tasks')}>跑 Pipeline</button>
            <button className="btn" onClick={() => setView('ops-sources')}>数据源状态</button>
            <button className="btn" onClick={() => setView('ops-quality')}>质量审计</button>
          </div>
        </Card>
        {data.ai_reviews.length > 0 && (
          <Card>
            <h3>最近 AI 研判</h3>
            <div className="timeline" style={{ marginTop: 8 }}>
              {data.ai_reviews.slice(0, 3).map((r, i) => (
                <div key={i} className="timeline-item">
                  <b>{r.title}</b><br />
                  <span className="muted small">{r.summary.slice(0, 80)}{r.summary.length > 80 ? '...' : ''}</span>
                </div>
              ))}
            </div>
          </Card>
        )}
        {data.ai_associations.length > 0 && (
          <Card>
            <h3>最近资产关联</h3>
            <div className="timeline" style={{ marginTop: 8 }}>
              {data.ai_associations.slice(0, 3).map((a, i) => (
                <div key={i} className="timeline-item">
                  <b>{a.title}</b><br />
                  <span className="muted small">{a.summary.slice(0, 80)}{a.summary.length > 80 ? '...' : ''}</span>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </div>
  );
}
