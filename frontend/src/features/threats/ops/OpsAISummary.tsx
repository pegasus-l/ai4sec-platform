import { useQuery } from '@tanstack/react-query';
import { Card } from '../../../components/ui';
import { fetchOpsAISummary } from '../../../api/opsClient';
import type { ThreatRepo, ThreatAsset } from '../../../types/threat';

interface Props {
  openRepo: (repo: ThreatRepo) => void;
  openAsset: (asset: ThreatAsset) => void;
}

export function OpsAISummary({ openRepo, openAsset }: Props) {
  const { data, isLoading } = useQuery({ queryKey: ['ops-ai-summary'], queryFn: fetchOpsAISummary, staleTime: 5000 });

  if (isLoading || !data) return <p className="muted">加载中...</p>;

  const reviews = data.ai_reviews;
  const assocs = data.asset_associations;

  return (
    <div className="grid">
      <div className="grid cols-2">
        <Card className="kpi"><span>AI 研判</span><strong>{reviews.count}</strong><p>已完成分析的代码仓</p></Card>
        <Card className="kpi"><span>资产关联</span><strong>{assocs.count}</strong><p>已完成关联的资产</p></Card>
      </div>

      <Card style={{ marginTop: 12 }}>
        <h3>AI 研判结果</h3>
        {reviews.items.length > 0 ? (
          <div className="timeline" style={{ marginTop: 10 }}>
            {reviews.items.map((r, i) => (
              <div key={i} className="timeline-item clickable" onClick={() => {
                const repo: ThreatRepo = { id: String(r.item_id), title: r.title, org: r.title.split('/')[0] || '', name: r.title.split('/')[1] || r.title, url: r.url, summary: '', score: r.score, grade: '', status: '', surface: '', stars: 0, cve: 0, sa: 0, sec: 0, filtered: false, breakdown: {}, reasons: [], evidence: [], assets: [], raw: {} };
                openRepo(repo);
              }}>
                <div className="row-title"><b>{r.title}</b><span className={`badge ${r.score >= 70 ? 'A' : 'B'}`}>score {r.score}</span></div>
                {r.calibrated_surface && <span className="muted small">校准: {r.calibrated_surface.slice(0, 80)}</span>}
                <br />
                <span className="muted small">{r.summary.slice(0, 100)}{r.summary.length > 100 ? '...' : ''}</span>
                {r.confidence > 0 && <span className="badge" style={{ marginLeft: 8 }}>置信度 {Math.round(r.confidence * 100)}%</span>}
              </div>
            ))}
          </div>
        ) : <p className="muted">暂无 AI 研判记录。请在代码仓详情页点击"开始 AI 研判"。</p>}
      </Card>

      <Card style={{ marginTop: 12 }}>
        <h3>资产关联结果</h3>
        {assocs.items.length > 0 ? (
          <div className="timeline" style={{ marginTop: 10 }}>
            {assocs.items.map((a, i) => (
              <div key={i} className="timeline-item clickable" onClick={() => {
                const asset: ThreatAsset = { id: String(a.item_id), title: a.title, source: a.source, sourceType: '', category: '', url: '', summary: '', score: 0, status: '', tags: [], raw: {} };
                openAsset(asset);
              }}>
                <div className="row-title"><b>{a.title}</b><span className="badge">{a.source}</span></div>
                <span className="muted small">{a.summary.slice(0, 100)}{a.summary.length > 100 ? '...' : ''}</span>
                <br />
                <span className="badge" style={{ marginTop: 4 }}>{a.associations.length} 个关联仓库</span>
              </div>
            ))}
          </div>
        ) : <p className="muted">暂无资产关联记录。请在资产详情页点击"开始 AI 关联分析"。</p>}
      </Card>
    </div>
  );
}
